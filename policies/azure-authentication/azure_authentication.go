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

// Package azureauthentication implements the azure-authentication policy: it obtains a
// Microsoft Entra ID access token for the gateway's own Azure identity and injects it into the
// request before it is forwarded to an Azure-hosted backend such as Azure AI Foundry.
package azureauthentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthenticationTypeWorkloadIdentity exchanges the pod's AKS Workload Identity federated
	// token for an access token.
	AuthenticationTypeWorkloadIdentity = "workload-identity"

	// AuthenticationTypeManagedIdentity gets the access token from the Azure Instance Metadata
	// Service (IMDS) for an identity assigned to the VM, VM scale set or AKS node.
	AuthenticationTypeManagedIdentity = "managed-identity"

	// AuthType is the AuthContext.AuthType value recorded for workload-identity.
	AuthType = "azure-workload-identity"

	// AuthTypeManagedIdentity is the AuthContext.AuthType value recorded for managed-identity.
	AuthTypeManagedIdentity = "azure-managed-identity"

	// systemAssignedCredentialID is the AuthContext.CredentialID of the system-assigned identity,
	// which has no client ID in the configuration.
	systemAssignedCredentialID = "system-assigned"

	defaultScope               = "https://ai.azure.com/.default"
	defaultHeaderName          = "Authorization"
	defaultValuePrefix         = "Bearer"
	defaultTokenRequestTimeout = 10 * time.Second

	// maxTokenRequestTimeout keeps a token fetch well inside the ext_proc message timeout.
	maxTokenRequestTimeout = 30 * time.Second

	failureMessage = "failed to authenticate request to upstream Azure service"
)

var (
	// scopePattern accepts a single client-credentials scope: a resource followed by /.default.
	scopePattern = regexp.MustCompile(`^\S+/\.default$`)

	// headerNamePattern is an RFC 9110 token, which also rules out pseudo-headers.
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

	// entraErrorCodePattern matches an OAuth error code such as invalid_client.
	entraErrorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

	// tokenRequestTimeoutPattern is the definition's pattern for tokenRequestTimeout: whole seconds
	// from 1s to 30s or milliseconds from 1ms to 30000ms. It is checked here too because a value
	// given through an LLM provider's upstream.auth reaches the policy unvalidated.
	tokenRequestTimeoutPattern = regexp.MustCompile(`^(([1-9]|[12][0-9]|30)s|([1-9][0-9]{0,3}|[12][0-9]{4}|30000)ms)$`)

	// registry holds the token sources shared by every policy instance in the process.
	registry = newSourceRegistry()

	// newTokenFetcher builds the client that obtains tokens for an identity: the Entra ID token
	// endpoint for a workload identity, IMDS for a managed identity.
	newTokenFetcher = func(id identityConfig) tokenFetcher {
		if id.authenticationType == AuthenticationTypeWorkloadIdentity {
			return newTokenClient(id.workload, sharedTransport())
		}
		return newIMDSClient(id.managed, imdsTransport())
	}
)

// identityConfig is the resolved identity of a policy instance. Only the field for its
// authenticationType is set, so the struct is comparable and serves as part of a token cache key.
type identityConfig struct {
	authenticationType string
	workload           workloadIdentityConfig // set for workload-identity
	managed            managedIdentityConfig  // set for managed-identity
}

// tokenService names where a policy's tokens come from, for fault reasons and the failure log.
type tokenService struct {
	name     string // e.g. "Microsoft Entra ID"
	endpoint string // e.g. "the Microsoft Entra ID token endpoint"
}

var (
	entraService = tokenService{name: "Microsoft Entra ID", endpoint: "the Microsoft Entra ID token endpoint"}
	imdsService  = tokenService{name: "the Azure Instance Metadata Service", endpoint: "the Azure Instance Metadata Service"}
)

// resolveIdentity resolves the identity the policy params and the environment describe.
func resolveIdentity(p params, getenv func(string) string) (identityConfig, error) {
	if p.authenticationType == AuthenticationTypeManagedIdentity {
		cfg, err := resolveManagedIdentityConfig(p.clientID, getenv)
		if err != nil {
			return identityConfig{}, fmt.Errorf("managed identity is not available: %w", err)
		}
		return identityConfig{authenticationType: AuthenticationTypeManagedIdentity, managed: cfg}, nil
	}

	cfg, err := resolveWorkloadIdentityConfig(p.clientID, p.tenantID, getenv)
	if err != nil {
		return identityConfig{}, fmt.Errorf("workload identity is not available: %w", err)
	}
	return identityConfig{authenticationType: AuthenticationTypeWorkloadIdentity, workload: cfg}, nil
}

// Policy injects an Entra ID access token for the gateway's workload identity or managed identity
// into a request header before the request is forwarded upstream.
type Policy struct {
	authenticationType string
	scope              string
	tenantID           string // workload-identity only
	clientID           string // "" for a system-assigned managed identity
	headerName         string
	valuePrefix        string
	service            tokenService
	source             *tokenSource
}

type params struct {
	authenticationType  string
	scope               string
	clientID            string
	tenantID            string
	headerName          string
	valuePrefix         string
	tokenRequestTimeout time.Duration
}

// GetPolicy is the v1alpha2 factory entry point. The policy engine calls it once per route the
// policy is attached to; instances with the same identity, scope and timeout share one token.
func GetPolicy(metadata policy.PolicyMetadata, rawParams map[string]interface{}) (policy.Policy, error) {
	p, err := extractParams(rawParams)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	id, err := resolveIdentity(p, os.Getenv)
	if err != nil {
		return nil, err
	}

	pol := &Policy{
		authenticationType: p.authenticationType,
		scope:              p.scope,
		headerName:         p.headerName,
		valuePrefix:        p.valuePrefix,
	}
	if id.authenticationType == AuthenticationTypeManagedIdentity {
		pol.clientID = id.managed.clientID
		pol.service = imdsService
	} else {
		pol.tenantID, pol.clientID = id.workload.tenantID, id.workload.clientID
		pol.service = entraService
	}
	identityAttrs := pol.identityAttrs()

	pol.source = registry.get(sourceKey{identity: id, scope: p.scope, timeout: p.tokenRequestTimeout}, func() *tokenSource {
		return newTokenSource(newTokenFetcher(id), p.scope, p.tokenRequestTimeout, identityAttrs)
	})

	slog.Debug("AzureAuthentication: policy initialized", append(append([]any{
		"route", metadata.RouteName, "apiName", metadata.APIName, "authenticationType", p.authenticationType},
		identityAttrs...), "headerName", p.headerName)...)

	return pol, nil
}

// identityAttrs are the log attributes naming the policy's identity and scope: the tenant only
// for workload-identity, and system-assigned for a managed identity without a client ID.
func (p *Policy) identityAttrs() []any {
	if p.authenticationType == AuthenticationTypeManagedIdentity {
		return []any{"clientId", p.credentialID(), "scope", p.scope}
	}
	return []any{"tenantId", p.tenantID, "clientId", p.clientID, "scope", p.scope}
}

// credentialID is the identity's client ID, or system-assigned for a system-assigned managed
// identity.
func (p *Policy) credentialID() string {
	if p.clientID == "" {
		return systemAssignedCredentialID
	}
	return p.clientID
}

func extractParams(raw map[string]interface{}) (params, error) {
	var p params
	var err error

	if p.authenticationType, err = requiredString(raw, "authenticationType"); err != nil {
		return p, err
	}
	if p.authenticationType != AuthenticationTypeWorkloadIdentity && p.authenticationType != AuthenticationTypeManagedIdentity {
		return p, fmt.Errorf("'authenticationType' must be %q or %q", AuthenticationTypeWorkloadIdentity, AuthenticationTypeManagedIdentity)
	}

	if p.scope, err = optionalString(raw, "scope", defaultScope); err != nil {
		return p, err
	}
	if !scopePattern.MatchString(p.scope) {
		return p, fmt.Errorf("'scope' must be a single scope ending in /.default, e.g. %s", defaultScope)
	}

	// Their formats are checked when the identity is resolved. For workload-identity both fall back
	// to the environment; a managed identity's tenant comes from the identity itself.
	if p.clientID, err = optionalString(raw, "clientId", ""); err != nil {
		return p, err
	}
	if p.tenantID, err = optionalString(raw, "tenantId", ""); err != nil {
		return p, err
	}
	if p.authenticationType == AuthenticationTypeManagedIdentity && p.tenantID != "" {
		return p, fmt.Errorf("'tenantId' is not used with authenticationType %q", AuthenticationTypeManagedIdentity)
	}

	if p.headerName, err = optionalString(raw, "headerName", defaultHeaderName); err != nil {
		return p, err
	}
	if !headerNamePattern.MatchString(p.headerName) {
		return p, errors.New("'headerName' must be a valid HTTP header name")
	}

	if p.valuePrefix, err = optionalString(raw, "valuePrefix", defaultValuePrefix); err != nil {
		return p, err
	}
	if strings.ContainsFunc(p.valuePrefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return p, errors.New("'valuePrefix' must not contain control characters")
	}

	timeout, err := optionalString(raw, "tokenRequestTimeout", "")
	if err != nil {
		return p, err
	}
	p.tokenRequestTimeout = defaultTokenRequestTimeout
	if timeout != "" {
		d, err := time.ParseDuration(timeout)
		if !tokenRequestTimeoutPattern.MatchString(timeout) || err != nil || d > maxTokenRequestTimeout {
			return p, errors.New("'tokenRequestTimeout' must be whole seconds from 1s to 30s or milliseconds from 1ms to 30000ms, e.g. \"10s\"")
		}
		p.tokenRequestTimeout = d
	}
	return p, nil
}

// requiredString returns a trimmed, non-empty string param.
func requiredString(raw map[string]interface{}, key string) (string, error) {
	v, ok := raw[key]
	if !ok {
		return "", fmt.Errorf("'%s' is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return s, nil
}

// optionalString returns a trimmed string param, or def when the key is absent. An explicitly
// empty string is returned as "" (so valuePrefix: "" means no prefix).
func optionalString(raw map[string]interface{}, key, def string) (string, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

// Mode reports that only request headers are processed: the policy sets one header and never
// needs the body or the response.
func (p *Policy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestHeaders injects the access token into headerName.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	tok, err := p.source.Token(ctx)
	if err != nil {
		return p.authFailure(reqCtx, err)
	}
	p.recordAuth(reqCtx, true)
	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{p.headerName: headerValue(p.valuePrefix, tok.value)},
	}
}

func headerValue(prefix, token string) string {
	if prefix == "" {
		return token
	}
	return prefix + " " + token
}

// authFailure returns 502: the caller's request was fine, it is the gateway's own upstream
// credential that could not be obtained. The client sees a generic message; the reason goes to
// fault policies (Description) and the log.
func (p *Policy) authFailure(reqCtx *policy.RequestHeaderContext, err error) policy.RequestHeaderAction {
	reason := faultReason(err, p.service)
	attrs := append([]any{"reason", reason, "error", err}, p.identityAttrs()...)
	if reqCtx != nil && reqCtx.SharedContext != nil {
		attrs = append(attrs, "requestId", reqCtx.RequestID, "apiName", reqCtx.APIName)
	}
	slog.Error("AzureAuthentication: could not obtain an access token from "+p.service.name, attrs...)

	p.recordAuth(reqCtx, false)

	body, _ := json.Marshal(map[string]string{"error": "Bad Gateway", "message": failureMessage})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
		IsFault:    true,
		Fault: &policy.FaultDetails{
			Code:        policy.FaultCodeMediationFailed,
			Type:        policy.FaultTypeMediation,
			Direction:   policy.DirectionRequest,
			Message:     failureMessage,
			Description: reason,
		},
	}
}

// faultReason is a short, client-free description of why no token could be obtained from svc. It
// names the OAuth error code when the service returned one, never the service's error text.
func faultReason(err error, svc tokenService) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out obtaining an access token from " + svc.name
	}
	var e *tokenRequestError
	if errors.As(err, &e) {
		switch e.kind {
		case errKindAssertion:
			return "the federated service account token could not be read"
		case errKindTransport:
			return svc.endpoint + " could not be reached"
		case errKindEndpoint:
			if entraErrorCodePattern.MatchString(e.code) {
				return fmt.Sprintf("%s rejected the token request (%s)", svc.name, e.code)
			}
			return fmt.Sprintf("%s returned HTTP %d", svc.endpoint, e.status)
		case errKindResponse:
			return svc.endpoint + " returned an unusable response"
		}
	}
	return "could not obtain an access token from " + svc.name
}

// recordAuth records the outcome in the shared AuthContext, keeping any earlier context (such
// as the inbound api-key-auth result) as Previous.
func (p *Policy) recordAuth(reqCtx *policy.RequestHeaderContext, ok bool) {
	if reqCtx == nil || reqCtx.SharedContext == nil {
		return
	}
	authType := AuthType
	props := map[string]string{
		"authenticationType": p.authenticationType,
		"scope":              p.scope,
	}
	if p.authenticationType == AuthenticationTypeManagedIdentity {
		authType = AuthTypeManagedIdentity
	} else {
		props["tenantId"] = p.tenantID
	}
	reqCtx.AuthContext = &policy.AuthContext{
		Authenticated: ok,
		AuthType:      authType,
		CredentialID:  p.credentialID(),
		Properties:    props,
		Previous:      reqCtx.AuthContext,
	}
}
