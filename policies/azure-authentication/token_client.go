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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Environment variables the AKS Workload Identity webhook injects into a pod whose service
// account is federated with a Microsoft Entra ID identity.
const (
	envTenantID           = "AZURE_TENANT_ID"
	envClientID           = "AZURE_CLIENT_ID"
	envFederatedTokenFile = "AZURE_FEDERATED_TOKEN_FILE"
	envAuthorityHost      = "AZURE_AUTHORITY_HOST"
)

const (
	// defaultAuthorityHost is the Azure public cloud's Entra ID host. Sovereign clouds set
	// AZURE_AUTHORITY_HOST instead.
	defaultAuthorityHost = "https://login.microsoftonline.com"

	// clientAssertionType is the RFC 7523 assertion type for a federated (JWT) credential.
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// maxFederatedTokenBytes bounds how much of the federated token file is read. A projected
	// service account token is a few KiB.
	maxFederatedTokenBytes = 64 << 10

	// maxTokenResponseBytes bounds how much of a token endpoint response is read, regardless of
	// Content-Length, so a misbehaving endpoint can't exhaust memory.
	maxTokenResponseBytes = 1 << 20

	// maxTokenRetries is how many times a transient failure (network error, 429, 5xx) is retried.
	maxTokenRetries = 2

	// retryBaseDelay and retryMaxDelay bound the exponential backoff between retries; jitter
	// keeps gateway replicas from retrying in lockstep.
	retryBaseDelay = 200 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	// refreshLead is how long before expiry a token is refreshed when the response carries no
	// refresh_in hint. Tokens living less than shortLivedTokenLifetime refresh at half-life.
	refreshLead             = 5 * time.Minute
	shortLivedTokenLifetime = 10 * time.Minute

	// maxLoggedDescriptionLen bounds the Entra error_description kept in an error message.
	maxLoggedDescriptionLen = 300
)

var (
	// guidPattern matches an Entra application (client) ID.
	guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// tenantPattern matches a tenant GUID or a domain name. The tenant is placed in the token URL
	// path, so anything that could change the path ("/", "?", "%", "..") is rejected.
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)*$`)
)

// workloadIdentityConfig is the resolved identity a token is requested for.
type workloadIdentityConfig struct {
	authorityHost string // https scheme and host (plus optional path), no trailing slash
	tenantID      string
	clientID      string
	tokenFile     string
}

// tokenEndpoint returns the Microsoft identity platform v2.0 token endpoint for the tenant.
func (c workloadIdentityConfig) tokenEndpoint() string {
	return c.authorityHost + "/" + c.tenantID + "/oauth2/v2.0/token"
}

// resolveWorkloadIdentityConfig combines the optional clientId/tenantId policy params with the
// environment the Workload Identity webhook injects. The token file path and authority host are
// only ever taken from the environment: if both came from API configuration, whoever writes an
// API could make the gateway send any file it can read to a host of their choosing.
func resolveWorkloadIdentityConfig(clientIDParam, tenantIDParam string, getenv func(string) string) (workloadIdentityConfig, error) {
	var cfg workloadIdentityConfig

	tenant, err := paramOrEnv(tenantIDParam, "tenantId", envTenantID, getenv)
	if err != nil {
		return cfg, err
	}
	if !tenantPattern.MatchString(tenant.value) {
		return cfg, fmt.Errorf("%s must be a tenant ID (GUID) or a domain name", tenant.source)
	}

	client, err := paramOrEnv(clientIDParam, "clientId", envClientID, getenv)
	if err != nil {
		return cfg, err
	}
	if !guidPattern.MatchString(client.value) {
		return cfg, fmt.Errorf("%s must be an application (client) ID in GUID form", client.source)
	}

	tokenFile := strings.TrimSpace(getenv(envFederatedTokenFile))
	if tokenFile == "" {
		return cfg, fmt.Errorf("the %s environment variable is not set; it is normally injected by the AKS Workload Identity webhook", envFederatedTokenFile)
	}

	authority, err := resolveAuthorityHost(strings.TrimSpace(getenv(envAuthorityHost)))
	if err != nil {
		return cfg, err
	}

	return workloadIdentityConfig{
		authorityHost: authority,
		tenantID:      tenant.value,
		clientID:      client.value,
		tokenFile:     tokenFile,
	}, nil
}

type sourcedValue struct {
	value  string
	source string // the param or environment variable the value came from, for error messages
}

func paramOrEnv(param, paramName, envName string, getenv func(string) string) (sourcedValue, error) {
	if param != "" {
		return sourcedValue{value: param, source: "'" + paramName + "'"}, nil
	}
	if v := strings.TrimSpace(getenv(envName)); v != "" {
		return sourcedValue{value: v, source: "the " + envName + " environment variable"}, nil
	}
	return sourcedValue{}, fmt.Errorf("'%s' is not set and the %s environment variable is not set; it is normally injected by the AKS Workload Identity webhook", paramName, envName)
}

func resolveAuthorityHost(raw string) (string, error) {
	if raw == "" {
		return defaultAuthorityHost, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("the %s environment variable is not a valid URL", envAuthorityHost)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("the %s environment variable must use https", envAuthorityHost)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("the %s environment variable must be an https URL with a host and no credentials, query or fragment", envAuthorityHost)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// accessToken is an Entra ID access token and when to refresh it.
type accessToken struct {
	value     string
	expiresOn time.Time
	refreshAt time.Time
}

// tokenFetcher obtains a fresh access token for a scope. tokenClient is the production
// implementation; the token source depends only on this interface.
type tokenFetcher interface {
	fetchToken(ctx context.Context, scope string) (*accessToken, error)
}

// tokenClient exchanges the pod's federated service account token for an Entra ID access token
// (OAuth 2.0 client credentials grant with a client assertion).
type tokenClient struct {
	cfg        workloadIdentityConfig
	httpClient *http.Client
	now        func() time.Time
	sleep      func(ctx context.Context, d time.Duration) error
}

func newTokenClient(cfg workloadIdentityConfig, transport http.RoundTripper) *tokenClient {
	return &tokenClient{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			// The request carries a credential; never let a redirect send it somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   time.Now,
		sleep: sleepContext,
	}
}

var (
	sharedTransportOnce sync.Once
	sharedTransportVal  *http.Transport
)

// sharedTransport is the process-wide transport for token requests: proxy settings from the
// standard environment variables, TLS 1.2 or newer, and the system trust store (which honours
// SSL_CERT_FILE and SSL_CERT_DIR).
func sharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = http.ProxyFromEnvironment
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		sharedTransportVal = t
	})
	return sharedTransportVal
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetchToken requests a token, retrying transient failures (network errors, 429, 5xx) with
// backoff. It never waits past ctx's deadline: a Retry-After longer than the time left ends the
// fetch with the last error.
func (c *tokenClient) fetchToken(ctx context.Context, scope string) (*accessToken, error) {
	assertion, err := readFederatedToken(c.cfg.tokenFile)
	if err != nil {
		return nil, err
	}
	return fetchWithRetry(ctx, maxTokenRetries, c.sleep, func() (*accessToken, error) {
		return c.requestToken(ctx, scope, assertion)
	})
}

// fetchWithRetry calls request until it succeeds, fails with an error that is not retryable, or
// maxRetries retries are spent, waiting before each retry with retryDelay. It never waits past
// ctx's deadline: a delay longer than the time left ends the fetch with the last error.
func fetchWithRetry(ctx context.Context, maxRetries int, sleep func(context.Context, time.Duration) error, request func() (*accessToken, error)) (*accessToken, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt, lastErr)
			if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
				return nil, lastErr
			}
			if err := sleep(ctx, delay); err != nil {
				return nil, lastErr
			}
		}

		tok, err := request()
		if err == nil {
			return tok, nil
		}
		lastErr = err
		if ctx.Err() != nil || !isRetryable(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *tokenClient) requestToken(ctx context.Context, scope, assertion string) (*accessToken, error) {
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {c.cfg.clientID},
		"scope":                 {scope},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.tokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &tokenRequestError{kind: errKindTransport, cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		return nil, &tokenRequestError{kind: errKindResponse, status: resp.StatusCode, cause: errors.New("token endpoint response exceeds 1 MiB")}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newEndpointError(resp, body, entraRetryable)
	}
	return parseTokenResponse(body, issuedAt)
}

func readFederatedToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", &tokenRequestError{kind: errKindAssertion, cause: fmt.Errorf("opening the federated token file: %w", err)}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFederatedTokenBytes+1))
	if err != nil {
		return "", &tokenRequestError{kind: errKindAssertion, cause: fmt.Errorf("reading the federated token file: %w", err)}
	}
	if len(data) > maxFederatedTokenBytes {
		return "", &tokenRequestError{kind: errKindAssertion, cause: errors.New("the federated token file exceeds 64 KiB")}
	}
	assertion := string(bytes.TrimSpace(data))
	if assertion == "" {
		return "", &tokenRequestError{kind: errKindAssertion, cause: errors.New("the federated token file is empty")}
	}
	return assertion, nil
}

type tokenResponseBody struct {
	TokenType   string          `json:"token_type"`
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	RefreshIn   json.RawMessage `json:"refresh_in"`
}

func parseTokenResponse(body []byte, issuedAt time.Time) (*accessToken, error) {
	invalid := func(format string, args ...any) error {
		return &tokenRequestError{kind: errKindResponse, status: http.StatusOK, cause: fmt.Errorf(format, args...)}
	}

	var r tokenResponseBody
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, invalid("token endpoint response is not valid JSON")
	}
	if r.AccessToken == "" {
		return nil, invalid("token endpoint response has no access_token")
	}
	if !strings.EqualFold(r.TokenType, "Bearer") {
		return nil, invalid("token endpoint returned token_type %q, want Bearer", r.TokenType)
	}
	expiresIn, ok := parseSeconds(r.ExpiresIn)
	if !ok {
		return nil, invalid("token endpoint response has no valid expires_in")
	}

	lifetime := time.Duration(expiresIn) * time.Second
	tok := &accessToken{value: r.AccessToken, expiresOn: issuedAt.Add(lifetime)}
	switch refreshIn, ok := parseSeconds(r.RefreshIn); {
	case ok && refreshIn < expiresIn:
		tok.refreshAt = issuedAt.Add(time.Duration(refreshIn) * time.Second)
	case lifetime < shortLivedTokenLifetime:
		tok.refreshAt = issuedAt.Add(lifetime / 2)
	default:
		tok.refreshAt = tok.expiresOn.Add(-refreshLead)
	}
	return tok, nil
}

// parseSeconds reads a positive number of seconds sent as a JSON number or a numeric string.
func parseSeconds(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, false
		}
		if n, err = strconv.ParseInt(strings.TrimSpace(s), 10, 64); err != nil {
			return 0, false
		}
	}
	return n, n > 0
}

type errorKind int

const (
	errKindAssertion errorKind = iota // the federated token file could not be used
	errKindTransport                  // no usable response reached the gateway
	errKindEndpoint                   // the token endpoint answered with an error status
	errKindResponse                   // a 200 the gateway could not use
)

// tokenRequestError describes a failed token request. Its message is safe to log: it never
// contains the federated token or an access token.
type tokenRequestError struct {
	kind          errorKind
	status        int
	code          string // Entra "error", e.g. invalid_client
	errorCodes    []int  // Entra AADSTS codes
	description   string // Entra error_description, truncated
	correlationID string
	traceID       string
	retryable     bool
	retryAfter    time.Duration
	cause         error
}

func (e *tokenRequestError) Error() string {
	var b strings.Builder
	switch e.kind {
	case errKindAssertion:
		b.WriteString("federated token unusable")
	case errKindTransport:
		b.WriteString("token request failed")
	case errKindEndpoint:
		fmt.Fprintf(&b, "token endpoint returned HTTP %d", e.status)
	case errKindResponse:
		b.WriteString("invalid token endpoint response")
	}
	if e.code != "" {
		fmt.Fprintf(&b, " error=%s", e.code)
	}
	if len(e.errorCodes) > 0 {
		fmt.Fprintf(&b, " error_codes=%v", e.errorCodes)
	}
	if e.correlationID != "" {
		fmt.Fprintf(&b, " correlation_id=%s", e.correlationID)
	}
	if e.traceID != "" {
		fmt.Fprintf(&b, " trace_id=%s", e.traceID)
	}
	if e.description != "" {
		fmt.Fprintf(&b, " description=%q", e.description)
	}
	if e.cause != nil {
		fmt.Fprintf(&b, ": %v", e.cause)
	}
	return b.String()
}

func (e *tokenRequestError) Unwrap() error { return e.cause }

type errorResponseBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	TraceID          string `json:"trace_id"`
}

// entraRetryable reports whether Entra ID's answer is worth retrying: throttling or a server error.
func entraRetryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// newEndpointError describes an error status from a token endpoint. retryable decides, from the
// status, whether the request is tried again.
func newEndpointError(resp *http.Response, body []byte, retryable func(status int) bool) *tokenRequestError {
	e := &tokenRequestError{
		kind:      errKindEndpoint,
		status:    resp.StatusCode,
		retryable: retryable(resp.StatusCode),
	}
	var r errorResponseBody
	if json.Unmarshal(body, &r) == nil {
		e.code = r.Error
		e.errorCodes = r.ErrorCodes
		e.correlationID = r.CorrelationID
		e.traceID = r.TraceID
		e.description = truncate(r.ErrorDescription, maxLoggedDescriptionLen)
	}
	if e.retryable {
		e.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return e
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func isRetryable(err error) bool {
	var e *tokenRequestError
	return errors.As(err, &e) && e.retryable
}

// retryDelay is exponential backoff with jitter, or the endpoint's Retry-After when longer.
func retryDelay(attempt int, lastErr error) time.Duration {
	backoff := retryBaseDelay << (attempt - 1)
	if backoff > retryMaxDelay || backoff <= 0 {
		backoff = retryMaxDelay
	}
	backoff += rand.N(backoff/2 + 1)
	var e *tokenRequestError
	if errors.As(lastErr, &e) && e.retryAfter > backoff {
		return e.retryAfter
	}
	return backoff
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
