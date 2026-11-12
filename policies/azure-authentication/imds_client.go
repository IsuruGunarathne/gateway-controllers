/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package azureauthentication

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// envIMDSTokenEndpoint overrides the IMDS token endpoint, for testing: managed identity tokens
	// are then requested from that https URL instead of the link-local IMDS address.
	envIMDSTokenEndpoint = "AZURE_IMDS_TOKEN_ENDPOINT"

	// imdsTokenEndpoint is the Azure Instance Metadata Service's managed identity token endpoint.
	// Only the VM, VM scale set instance or AKS node the gateway runs on can reach it.
	imdsTokenEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

	imdsAPIVersion = "2018-02-01"

	// maxIMDSRetries bounds the retries of the answers Microsoft documents as transient for IMDS
	// (404, 410, 429 and 5xx). The whole fetch still ends at tokenRequestTimeout.
	maxIMDSRetries = 4
)

// managedIdentityConfig is the managed identity a token is requested for through IMDS.
type managedIdentityConfig struct {
	endpoint string // imdsTokenEndpoint, or the AZURE_IMDS_TOKEN_ENDPOINT override; no query
	clientID string // the user-assigned identity's client ID; "" selects the system-assigned identity
}

// resolveManagedIdentityConfig validates the optional clientId param and the endpoint override.
// AZURE_CLIENT_ID is not read: the AKS Workload Identity webhook sets it for the federated
// identity, which need not be an identity assigned to the node.
func resolveManagedIdentityConfig(clientIDParam string, getenv func(string) string) (managedIdentityConfig, error) {
	cfg := managedIdentityConfig{endpoint: imdsTokenEndpoint, clientID: clientIDParam}
	if cfg.clientID != "" && !guidPattern.MatchString(cfg.clientID) {
		return managedIdentityConfig{}, errors.New("'clientId' must be an application (client) ID in GUID form")
	}
	if raw := strings.TrimSpace(getenv(envIMDSTokenEndpoint)); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return managedIdentityConfig{}, fmt.Errorf("the %s environment variable must be an https URL with a host and no credentials, query or fragment", envIMDSTokenEndpoint)
		}
		cfg.endpoint = u.Scheme + "://" + u.Host + u.EscapedPath()
	}
	return cfg, nil
}

// resourceFromScope turns a client credentials scope into the resource IMDS expects.
func resourceFromScope(scope string) string {
	return strings.TrimSuffix(scope, "/.default")
}

// imdsRetryable reports whether an IMDS answer is worth retrying: 404 and 410 while IMDS is
// starting or updating, 429 while it is throttling, and any server error.
func imdsRetryable(status int) bool {
	return status == http.StatusNotFound || status == http.StatusGone ||
		status == http.StatusTooManyRequests || status >= 500
}

var (
	imdsTransportOnce sync.Once
	imdsTransportVal  *http.Transport
)

// imdsTransport is the process-wide transport for IMDS requests. It never uses a proxy, whatever
// the environment says: IMDS answers only on the host's own link-local address, and a proxy must
// not see these requests. TLS 1.2 or newer applies to an https endpoint override.
func imdsTransport() *http.Transport {
	imdsTransportOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		imdsTransportVal = t
	})
	return imdsTransportVal
}

// imdsClient requests access tokens for a managed identity from IMDS.
type imdsClient struct {
	cfg        managedIdentityConfig
	httpClient *http.Client
	now        func() time.Time
	sleep      func(ctx context.Context, d time.Duration) error
}

func newIMDSClient(cfg managedIdentityConfig, transport http.RoundTripper) *imdsClient {
	return &imdsClient{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			// The response carries a credential; never take it from wherever a redirect points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   time.Now,
		sleep: sleepContext,
	}
}

// fetchToken requests a token for the scope's resource, retrying the answers IMDS documents as
// transient. It never waits past ctx's deadline.
func (c *imdsClient) fetchToken(ctx context.Context, scope string) (*accessToken, error) {
	resource := resourceFromScope(scope)
	return fetchWithRetry(ctx, maxIMDSRetries, c.sleep, func() (*accessToken, error) {
		return c.requestToken(ctx, resource)
	})
}

func (c *imdsClient) requestToken(ctx context.Context, resource string) (*accessToken, error) {
	query := url.Values{"api-version": {imdsAPIVersion}, "resource": {resource}}
	if c.cfg.clientID != "" {
		query.Set("client_id", c.cfg.clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, &tokenRequestError{kind: errKindTransport, cause: err}
	}
	req.Header.Set("Metadata", "true")
	req.Header.Set("Accept", "application/json")

	issuedAt := c.now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &tokenRequestError{kind: errKindTransport, retryable: true, cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, &tokenRequestError{kind: errKindTransport, status: resp.StatusCode, retryable: true, cause: err}
	}
	if len(body) > maxTokenResponseBytes {
		return nil, &tokenRequestError{kind: errKindResponse, status: resp.StatusCode, cause: errors.New("IMDS response exceeds 1 MiB")}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newEndpointError(resp, body, imdsRetryable)
	}
	return parseTokenResponse(body, issuedAt)
}
