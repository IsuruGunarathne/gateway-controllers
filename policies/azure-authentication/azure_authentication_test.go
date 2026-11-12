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
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// setWorkloadIdentityEnv sets the variables the AKS Workload Identity webhook injects.
func setWorkloadIdentityEnv(t *testing.T, tokenFile string) {
	t.Setenv("AZURE_TENANT_ID", testTenantID)
	t.Setenv("AZURE_CLIENT_ID", testClientID)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	t.Setenv("AZURE_AUTHORITY_HOST", "")
}

// useFetcher replaces the token endpoint client for one test and gives it an empty registry, so
// no cached token leaks between tests.
func useFetcher(t *testing.T, build func(id identityConfig) tokenFetcher) {
	t.Helper()
	prevBuild, prevRegistry := newTokenFetcher, registry
	newTokenFetcher = build
	registry = newSourceRegistry()
	t.Cleanup(func() { newTokenFetcher, registry = prevBuild, prevRegistry })
}

func staticFetcher(value string) *fakeFetcher {
	return &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
		return hourToken(value, time.Now()), nil
	}}
}

func newRequestHeaderContext(shared *policy.SharedContext) *policy.RequestHeaderContext {
	if shared == nil {
		shared = &policy.SharedContext{RequestID: "req-1", APIName: "foundry"}
	}
	return &policy.RequestHeaderContext{
		SharedContext: shared,
		Headers:       policy.NewHeaders(map[string][]string{}),
		Path:          "/models/chat/completions",
		Method:        http.MethodPost,
		Authority:     "gateway.example.com",
		Scheme:        "https",
	}
}

func mustGetPolicy(t *testing.T, params map[string]interface{}) *Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{RouteName: "route-1", APIName: "foundry"}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return p.(*Policy)
}

func requireHeaderMods(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("action = %#v, want UpstreamRequestHeaderModifications", action)
	}
	return mods
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func TestGetPolicyRejectsInvalidParams(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	useFetcher(t, func(identityConfig) tokenFetcher { return staticFetcher("tok") })

	valid := func(extra map[string]interface{}) map[string]interface{} {
		params := map[string]interface{}{"authenticationType": "workload-identity"}
		for k, v := range extra {
			params[k] = v
		}
		return params
	}

	tests := []struct {
		name        string
		params      map[string]interface{}
		wantInError string
	}{
		{name: "missing authenticationType", params: map[string]interface{}{}, wantInError: "authenticationType"},
		{name: "non-string authenticationType", params: map[string]interface{}{"authenticationType": 1}, wantInError: "authenticationType"},
		{name: "unsupported authenticationType", params: map[string]interface{}{"authenticationType": "client-secret"}, wantInError: "managed-identity"},
		{name: "managed-identity with tenantId", params: map[string]interface{}{"authenticationType": "managed-identity", "tenantId": "contoso.onmicrosoft.com"}, wantInError: `'tenantId' is not used with authenticationType "managed-identity"`},
		{name: "managed-identity with a clientId that is not a GUID", params: map[string]interface{}{"authenticationType": "managed-identity", "clientId": "my-app"}, wantInError: "clientId"},
		{name: "scope without .default", params: valid(map[string]interface{}{"scope": "https://ai.azure.com"}), wantInError: "scope"},
		{name: "two scopes", params: valid(map[string]interface{}{"scope": "https://ai.azure.com/.default https://graph.microsoft.com/.default"}), wantInError: "scope"},
		{name: "non-string scope", params: valid(map[string]interface{}{"scope": 42}), wantInError: "scope"},
		{name: "clientId not a GUID", params: valid(map[string]interface{}{"clientId": "my-app"}), wantInError: "clientId"},
		{name: "tenantId with a slash", params: valid(map[string]interface{}{"tenantId": "a/b"}), wantInError: "tenantId"},
		{name: "empty headerName", params: valid(map[string]interface{}{"headerName": ""}), wantInError: "headerName"},
		{name: "headerName with a space", params: valid(map[string]interface{}{"headerName": "Bad Header"}), wantInError: "headerName"},
		{name: "pseudo-header", params: valid(map[string]interface{}{"headerName": ":authority"}), wantInError: "headerName"},
		{name: "valuePrefix with a line break", params: valid(map[string]interface{}{"valuePrefix": "Bearer\r\nX-Injected: 1"}), wantInError: "valuePrefix"},
		{name: "unparsable timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "soon"}), wantInError: "tokenRequestTimeout"},
		{name: "zero timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "0s"}), wantInError: "tokenRequestTimeout"},
		{name: "negative timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "-1s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30s", params: valid(map[string]interface{}{"tokenRequestTimeout": "45s"}), wantInError: "tokenRequestTimeout"},
		{name: "non-string timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": 10}), wantInError: "tokenRequestTimeout"},
		{name: "fractional seconds timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1.5s"}), wantInError: "tokenRequestTimeout"},
		{name: "minutes timeout", params: valid(map[string]interface{}{"tokenRequestTimeout": "1m"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout with a leading zero", params: valid(map[string]interface{}{"tokenRequestTimeout": "05s"}), wantInError: "tokenRequestTimeout"},
		{name: "timeout over 30000ms", params: valid(map[string]interface{}{"tokenRequestTimeout": "30001ms"}), wantInError: "tokenRequestTimeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPolicy(policy.PolicyMetadata{}, tt.params)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantInError) {
				t.Fatalf("error %q does not mention %q", err, tt.wantInError)
			}
		})
	}
}

func TestGetPolicyFailsWithoutWorkloadIdentityEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, "")
	useFetcher(t, func(identityConfig) tokenFetcher { return staticFetcher("tok") })

	_, err := GetPolicy(policy.PolicyMetadata{}, map[string]interface{}{"authenticationType": "workload-identity"})
	if err == nil || !strings.Contains(err.Error(), "AZURE_FEDERATED_TOKEN_FILE") {
		t.Fatalf("error = %v, want one naming AZURE_FEDERATED_TOKEN_FILE", err)
	}
}

func TestOnRequestHeadersSetsBearerToken(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	f := staticFetcher("tok-1")
	var gotCfg workloadIdentityConfig
	useFetcher(t, func(id identityConfig) tokenFetcher { gotCfg = id.workload; return f })

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "  workload-identity  "})
	mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if len(mods.HeadersToSet) != 1 || mods.HeadersToSet["Authorization"] != "Bearer tok-1" {
		t.Fatalf("HeadersToSet = %v, want Authorization: Bearer tok-1", mods.HeadersToSet)
	}
	if len(mods.HeadersToRemove) != 0 || len(mods.HeadersToAppend) != 0 {
		t.Fatalf("unexpected header changes: %+v", mods)
	}
	if f.scopes[0] != "https://ai.azure.com/.default" {
		t.Fatalf("scope = %q, want the Foundry default", f.scopes[0])
	}
	if gotCfg.tenantID != testTenantID || gotCfg.clientID != testClientID || gotCfg.tokenFile != "/token" {
		t.Fatalf("identity = %+v", gotCfg)
	}
}

func TestOnRequestHeadersUsesConfiguredHeaderPrefixAndScope(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]interface{}
		wantHeader string
		wantValue  string
		wantScope  string
	}{
		{
			name:       "custom header without prefix",
			params:     map[string]interface{}{"headerName": "X-Upstream-Token", "valuePrefix": ""},
			wantHeader: "X-Upstream-Token", wantValue: "tok-1", wantScope: "https://ai.azure.com/.default",
		},
		{
			name:       "custom prefix",
			params:     map[string]interface{}{"valuePrefix": "Token"},
			wantHeader: "Authorization", wantValue: "Token tok-1", wantScope: "https://ai.azure.com/.default",
		},
		{
			name:       "cognitive services scope",
			params:     map[string]interface{}{"scope": "https://cognitiveservices.azure.com/.default"},
			wantHeader: "Authorization", wantValue: "Bearer tok-1", wantScope: "https://cognitiveservices.azure.com/.default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setWorkloadIdentityEnv(t, "/token")
			f := staticFetcher("tok-1")
			useFetcher(t, func(identityConfig) tokenFetcher { return f })
			tt.params["authenticationType"] = "workload-identity"

			p := mustGetPolicy(t, tt.params)
			mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

			if len(mods.HeadersToSet) != 1 || mods.HeadersToSet[tt.wantHeader] != tt.wantValue {
				t.Fatalf("HeadersToSet = %v, want %s: %s", mods.HeadersToSet, tt.wantHeader, tt.wantValue)
			}
			if f.scopes[0] != tt.wantScope {
				t.Fatalf("scope = %q, want %q", f.scopes[0], tt.wantScope)
			}
		})
	}
}

func TestOnRequestHeadersUsesIdentityOverrides(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	var gotCfg workloadIdentityConfig
	useFetcher(t, func(id identityConfig) tokenFetcher { gotCfg = id.workload; return staticFetcher("tok") })

	mustGetPolicy(t, map[string]interface{}{
		"authenticationType": "workload-identity",
		"clientId":           "99999999-8888-7777-6666-555555555555",
		"tenantId":           "contoso.onmicrosoft.com",
	})
	if gotCfg.clientID != "99999999-8888-7777-6666-555555555555" || gotCfg.tenantID != "contoso.onmicrosoft.com" {
		t.Fatalf("identity = %+v, want the overrides", gotCfg)
	}
}

// TestTokenRequestTimeoutFormats pins the formats the policy definition's pattern admits, so a
// value given through an LLM provider's upstream.auth, which the controller does not validate,
// behaves exactly like one on an API.
func TestTokenRequestTimeoutFormats(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"":        defaultTokenRequestTimeout,
		"1s":      time.Second,
		"30s":     30 * time.Second,
		"1ms":     time.Millisecond,
		"500ms":   500 * time.Millisecond,
		"30000ms": 30 * time.Second,
	} {
		raw := map[string]interface{}{"authenticationType": "workload-identity"}
		if value != "" {
			raw["tokenRequestTimeout"] = value
		}
		p, err := extractParams(raw)
		if err != nil {
			t.Fatalf("tokenRequestTimeout %q: unexpected error %v", value, err)
		}
		if p.tokenRequestTimeout != want {
			t.Fatalf("tokenRequestTimeout %q = %v, want %v", value, p.tokenRequestTimeout, want)
		}
	}
}

func TestTokenRequestTimeoutParamBoundsTheFetch(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	f := staticFetcher("tok")
	useFetcher(t, func(identityConfig) tokenFetcher { return f })

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "tokenRequestTimeout": "3s"})
	before := time.Now()
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))

	if len(f.deadlines) != 1 {
		t.Fatal("fetch ran without a deadline")
	}
	if d := f.deadlines[0].Sub(before); d <= 0 || d > 4*time.Second {
		t.Fatalf("fetch deadline %v after the request, want about 3s", d)
	}
}

func TestOnRequestHeadersRecordsAuthContext(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	useFetcher(t, func(identityConfig) tokenFetcher { return staticFetcher("tok-1") })
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

	got := shared.AuthContext
	if got == nil || !got.Authenticated || got.AuthType != "azure-workload-identity" || got.CredentialID != testClientID {
		t.Fatalf("AuthContext = %+v", got)
	}
	wantProps := map[string]string{
		"authenticationType": "workload-identity",
		"scope":              "https://ai.azure.com/.default",
		"tenantId":           testTenantID,
	}
	if len(got.Properties) != len(wantProps) {
		t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
	}
	for k, v := range wantProps {
		if got.Properties[k] != v {
			t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
		}
	}
	if got.Previous != inbound {
		t.Fatal("the inbound AuthContext was not kept as Previous")
	}
}

func TestOnRequestHeadersFailureReturnsDeclaredFault(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	useFetcher(t, func(identityConfig) tokenFetcher {
		return &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
			return nil, &tokenRequestError{
				kind:        errKindEndpoint,
				status:      http.StatusBadRequest,
				code:        "invalid_client",
				errorCodes:  []int{700016},
				description: "AADSTS700016: Application with identifier 'x' was not found in the directory 'contoso'.",
			}
		}}
	})
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	action := p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action = %#v, want ImmediateResponse", action)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "application/json" {
		t.Errorf("headers = %v", resp.Headers)
	}
	if got, want := string(resp.Body), `{"error":"Bad Gateway","message":"failed to authenticate request to upstream Azure service"}`; got != want {
		t.Errorf("body = %s\nwant   %s", got, want)
	}
	if !resp.IsFault || resp.Fault == nil {
		t.Fatal("the rejection does not declare a fault")
	}
	f := resp.Fault
	if f.Code != policy.FaultCodeMediationFailed || f.Type != policy.FaultTypeMediation || f.Direction != policy.DirectionRequest {
		t.Errorf("fault = %+v", f)
	}
	if f.Message != "failed to authenticate request to upstream Azure service" {
		t.Errorf("fault message = %q", f.Message)
	}
	if !strings.Contains(f.Description, "invalid_client") {
		t.Errorf("fault description %q does not name the Entra error code", f.Description)
	}
	if strings.Contains(f.Description, "AADSTS") || strings.Contains(f.Description, "contoso") {
		t.Errorf("fault description leaks Entra's error text: %q", f.Description)
	}
	if shared.AuthContext == nil || shared.AuthContext.Authenticated || shared.AuthContext.Previous != inbound {
		t.Errorf("AuthContext = %+v, want unauthenticated with the inbound context as Previous", shared.AuthContext)
	}
}

// TestARequestThatEndsFirstIsNotAnIdentityFailure: a caller that leaves before the token arrives is
// not an Entra ID or IMDS failure, so it is logged at Debug with its own reason and does not mark
// the request unauthenticated.
func TestARequestThatEndsFirstIsNotAnIdentityFailure(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	logs := captureLogs(t)
	release := make(chan struct{})
	useFetcher(t, func(identityConfig) tokenFetcher {
		return &fakeFetcher{respond: func(ctx context.Context, _ int) (*accessToken, error) {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errors.New("never answered")
		}}
	})
	t.Cleanup(func() { close(release) })
	inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey"}
	shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, ok := p.OnRequestHeaders(ctx, newRequestHeaderContext(shared), nil).(policy.ImmediateResponse)
	if !ok || resp.StatusCode != http.StatusBadGateway || !resp.IsFault || resp.Fault == nil {
		t.Fatalf("response = %+v, want a declared 502", resp)
	}
	if resp.Fault.Description != "the request ended before an access token was available" {
		t.Fatalf("description = %q", resp.Fault.Description)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("a request that ended first was logged as an error:\n%s", logs)
	}
	if shared.AuthContext != inbound {
		t.Fatalf("AuthContext = %+v, want the inbound one untouched", shared.AuthContext)
	}
}

// TestARejectionIsLoggedOnceWhileCached: requests that get a cached rejection fail the same way
// but log at Debug, so a misconfigured identity logs one ERROR per token request, not per request.
func TestARejectionIsLoggedOnceWhileCached(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	logs := captureLogs(t)
	f := &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
		return nil, &tokenRequestError{kind: errKindEndpoint, status: http.StatusUnauthorized, code: "invalid_client"}
	}}
	useFetcher(t, func(identityConfig) tokenFetcher { return f })
	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})

	for i := 0; i < 3; i++ {
		resp, ok := p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil).(policy.ImmediateResponse)
		if !ok || resp.StatusCode != http.StatusBadGateway || resp.Fault == nil ||
			resp.Fault.Description != "Microsoft Entra ID rejected the token request (invalid_client)" {
			t.Fatalf("request %d: response = %+v, want the 502 for the rejection", i+1, resp)
		}
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	out := logs.String()
	if n := strings.Count(out, "level=ERROR"); n != 1 {
		t.Fatalf("ERROR lines = %d, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "could not obtain an access token from Microsoft Entra ID"); n != 3 {
		t.Fatalf("failure log lines = %d, want 3 (1 ERROR, 2 Debug):\n%s", n, out)
	}
}

func TestPoliciesWithTheSameIdentityShareOneToken(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	f := staticFetcher("tok-1")
	useFetcher(t, func(identityConfig) tokenFetcher { return f })
	params := map[string]interface{}{"authenticationType": "workload-identity"}

	for i := 0; i < 3; i++ { // e.g. three routes of one LLM provider
		p := mustGetPolicy(t, params)
		requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("token fetches = %d, want 1", n)
	}

	other := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": "https://cognitiveservices.azure.com/.default"})
	requireHeaderMods(t, other.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	if n := f.callCount(); n != 2 {
		t.Fatalf("token fetches = %d, want 2 (a different scope needs its own token)", n)
	}
}

// failWith returns the response of a policy built from params when every token fetch fails with
// fetchErr.
func failWith(t *testing.T, params map[string]interface{}, fetchErr error) policy.ImmediateResponse {
	t.Helper()
	useFetcher(t, func(identityConfig) tokenFetcher {
		return &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) { return nil, fetchErr }}
	})
	action := mustGetPolicy(t, params).OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("action = %#v, want ImmediateResponse", action)
	}
	return resp
}

// TestWorkloadIdentityFaultReasonsAreUnchanged pins the fault reasons and the failure log line of
// workload-identity, which the integration suite asserts too.
func TestWorkloadIdentityFaultReasonsAreUnchanged(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", context.DeadlineExceeded, "timed out obtaining an access token from Microsoft Entra ID"},
		{"federated token", &tokenRequestError{kind: errKindAssertion, cause: errors.New("empty")}, "the federated service account token could not be read"},
		{"network", &tokenRequestError{kind: errKindTransport, cause: errors.New("dial")}, "the Microsoft Entra ID token endpoint could not be reached"},
		{"error with a code", &tokenRequestError{kind: errKindEndpoint, status: http.StatusUnauthorized, code: "invalid_client"}, "Microsoft Entra ID rejected the token request (invalid_client)"},
		{"error without a code", &tokenRequestError{kind: errKindEndpoint, status: http.StatusServiceUnavailable}, "the Microsoft Entra ID token endpoint returned HTTP 503"},
		{"unusable 200", &tokenRequestError{kind: errKindResponse, status: http.StatusOK, cause: errors.New("no token")}, "the Microsoft Entra ID token endpoint returned an unusable response"},
		{"anything else", errors.New("boom"), "could not obtain an access token from Microsoft Entra ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setWorkloadIdentityEnv(t, "/token")
			logs := captureLogs(t)
			resp := failWith(t, map[string]interface{}{"authenticationType": "workload-identity"}, tt.err)
			if resp.Fault == nil || resp.Fault.Description != tt.want {
				t.Fatalf("fault = %+v, want description %q", resp.Fault, tt.want)
			}
			if !strings.Contains(logs.String(), "AzureAuthentication: could not obtain an access token from Microsoft Entra ID") {
				t.Fatalf("log does not have the Entra ID failure line:\n%s", logs)
			}
		})
	}
}

func TestManagedIdentityFailureNamesIMDS(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	workload := failWith(t, map[string]interface{}{"authenticationType": "workload-identity"}, errors.New("boom"))

	tests := []struct {
		name string
		err  error
		want string
	}{
		{"error with a code", &tokenRequestError{kind: errKindEndpoint, status: http.StatusBadRequest, code: "invalid_request", description: "Identity not found"}, "the Azure Instance Metadata Service rejected the token request (invalid_request)"},
		{"error without a code", &tokenRequestError{kind: errKindEndpoint, status: http.StatusGone}, "the Azure Instance Metadata Service returned HTTP 410"},
		{"network", &tokenRequestError{kind: errKindTransport, cause: errors.New("dial")}, "the Azure Instance Metadata Service could not be reached"},
		{"deadline", context.DeadlineExceeded, "timed out obtaining an access token from the Azure Instance Metadata Service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			resp := failWith(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID}, tt.err)
			if resp.StatusCode != workload.StatusCode || !reflect.DeepEqual(resp.Headers, workload.Headers) || !bytes.Equal(resp.Body, workload.Body) {
				t.Fatalf("response = %d %v %s, want the workload-identity failure %d %v %s",
					resp.StatusCode, resp.Headers, resp.Body, workload.StatusCode, workload.Headers, workload.Body)
			}
			if !resp.IsFault || resp.Fault == nil || resp.Fault.Code != policy.FaultCodeMediationFailed {
				t.Fatalf("fault = %+v, want a declared %s", resp.Fault, policy.FaultCodeMediationFailed)
			}
			if resp.Fault.Description != tt.want {
				t.Fatalf("description = %q, want %q", resp.Fault.Description, tt.want)
			}
			if !strings.Contains(logs.String(), "could not obtain an access token from the Azure Instance Metadata Service") {
				t.Fatalf("log does not name IMDS:\n%s", logs)
			}
		})
	}
}

func TestGetPolicyBuildsManagedIdentityWithoutWorkloadIdentityEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_IMDS_TOKEN_ENDPOINT", "")
	var got identityConfig
	useFetcher(t, func(id identityConfig) tokenFetcher { got = id; return staticFetcher("tok") })

	mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity"})
	want := identityConfig{authenticationType: "managed-identity", managed: managedIdentityConfig{endpoint: imdsTokenEndpoint}}
	if got != want {
		t.Fatalf("identity = %+v, want %+v", got, want)
	}
}

func TestManagedIdentityIgnoresWorkloadIdentityEnvironment(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	var got identityConfig
	useFetcher(t, func(id identityConfig) tokenFetcher { got = id; return staticFetcher("tok") })

	mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity"})
	if got.authenticationType != "managed-identity" || got.managed.clientID != "" {
		t.Fatalf("identity = %+v, want the system-assigned identity, not AZURE_CLIENT_ID", got)
	}
}

func TestManagedIdentityUsesClientIDParam(t *testing.T) {
	var got identityConfig
	useFetcher(t, func(id identityConfig) tokenFetcher { got = id; return staticFetcher("tok") })

	mustGetPolicy(t, map[string]interface{}{"authenticationType": "managed-identity", "clientId": "11111111-2222-3333-4444-555555555555"})
	if got.managed.clientID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("identity = %+v, want the clientId param", got)
	}
}

func TestOnRequestHeadersRecordsManagedIdentityAuthContext(t *testing.T) {
	tests := []struct {
		name             string
		params           map[string]interface{}
		wantCredentialID string
	}{
		{"user-assigned", map[string]interface{}{"authenticationType": "managed-identity", "clientId": testClientID}, testClientID},
		// Without clientId, IMDS picks the host's system-assigned identity, or its only
		// user-assigned identity, so the policy cannot tell which one it got.
		{"host's default identity", map[string]interface{}{"authenticationType": "managed-identity"}, "host-default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFetcher(t, func(identityConfig) tokenFetcher { return staticFetcher("tok-1") })
			inbound := &policy.AuthContext{Authenticated: true, AuthType: "apikey", CredentialID: "app-1"}
			shared := &policy.SharedContext{RequestID: "req-1", AuthContext: inbound}

			p := mustGetPolicy(t, tt.params)
			requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(shared), nil))

			got := shared.AuthContext
			if got == nil || !got.Authenticated || got.AuthType != "azure-managed-identity" || got.CredentialID != tt.wantCredentialID {
				t.Fatalf("AuthContext = %+v", got)
			}
			wantProps := map[string]string{"authenticationType": "managed-identity", "scope": "https://ai.azure.com/.default"}
			if !reflect.DeepEqual(got.Properties, wantProps) {
				t.Fatalf("Properties = %v, want %v", got.Properties, wantProps)
			}
			if got.Previous != inbound {
				t.Fatal("the inbound AuthContext was not kept as Previous")
			}
		})
	}
}

func TestWorkloadAndManagedIdentitiesDoNotShareTokens(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	f := staticFetcher("tok")
	useFetcher(t, func(identityConfig) tokenFetcher { return f })

	for _, params := range []map[string]interface{}{
		{"authenticationType": "workload-identity"},
		{"authenticationType": "managed-identity"},
	} {
		p := mustGetPolicy(t, params)
		requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	}
	if n := f.callCount(); n != 2 {
		t.Fatalf("token fetches = %d, want 2 (each authentication type has its own token)", n)
	}
}

func TestNewTokenFetcherBuildsTheClientForTheAuthenticationType(t *testing.T) {
	workload := newTokenFetcher(identityConfig{
		authenticationType: AuthenticationTypeWorkloadIdentity,
		workload:           workloadIdentityConfig{authorityHost: defaultAuthorityHost, tenantID: testTenantID, clientID: testClientID, tokenFile: "/t"},
	})
	entra, ok := workload.(*tokenClient)
	if !ok {
		t.Fatalf("workload-identity fetcher = %T, want *tokenClient", workload)
	}
	if entra.httpClient.Transport != sharedTransport() {
		t.Fatal("the workload-identity client must use the shared Entra transport")
	}

	managed := newTokenFetcher(identityConfig{
		authenticationType: "managed-identity",
		managed:            managedIdentityConfig{endpoint: imdsTokenEndpoint},
	})
	imds, ok := managed.(*imdsClient)
	if !ok {
		t.Fatalf("managed-identity fetcher = %T, want *imdsClient", managed)
	}
	// IMDS requests must never go through HTTP(S)_PROXY, which the Entra transport honours.
	if imds.httpClient.Transport != imdsTransport() {
		t.Fatal("the managed-identity client must use the proxy-free IMDS transport")
	}
}

func TestModeProcessesOnlyRequestHeaders(t *testing.T) {
	setWorkloadIdentityEnv(t, "/token")
	useFetcher(t, func(identityConfig) tokenFetcher { return staticFetcher("tok") })

	got := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"}).Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("Mode() = %+v, want %+v", got, want)
	}
}

// TestEndToEndWithTokenEndpoint runs the policy with the real token client against a fake
// Entra ID endpoint, and checks that neither the access token nor the federated token is logged.
func TestEndToEndWithTokenEndpoint(t *testing.T) {
	logs := captureLogs(t)
	var fail atomic.Bool
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client", "error_codes": []int{700213}})
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse("access-token-secret", 3599))
	})
	setWorkloadIdentityEnv(t, writeAssertion(t, "federated-token-secret"))
	t.Setenv("AZURE_AUTHORITY_HOST", f.srv.URL)
	useFetcher(t, func(id identityConfig) tokenFetcher { return newTokenClient(id.workload, f.srv.Client().Transport) })

	p := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity"})
	mods := requireHeaderMods(t, p.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil))
	if mods.HeadersToSet["Authorization"] != "Bearer access-token-secret" {
		t.Fatalf("HeadersToSet = %v", mods.HeadersToSet)
	}
	if got := f.requests()[0].form.Get("client_assertion"); got != "federated-token-secret" {
		t.Fatalf("client_assertion = %q", got)
	}

	fail.Store(true)
	failing := mustGetPolicy(t, map[string]interface{}{"authenticationType": "workload-identity", "scope": "https://cognitiveservices.azure.com/.default"})
	if _, ok := failing.OnRequestHeaders(context.Background(), newRequestHeaderContext(nil), nil).(policy.ImmediateResponse); !ok {
		t.Fatal("expected a 502 ImmediateResponse")
	}

	out := logs.String()
	// 700213 appears only in the token endpoint error, not in the short fault reason.
	if !strings.Contains(out, "700213") {
		t.Errorf("failure was not logged with the token endpoint error:\n%s", out)
	}
	for _, secret := range []string{"access-token-secret", "federated-token-secret"} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain %q:\n%s", secret, out)
		}
	}
}
