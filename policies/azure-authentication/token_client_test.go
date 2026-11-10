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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testTenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	testClientID = "11111111-2222-3333-4444-555555555555"
)

var fixedNow = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func envFrom(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

// ---------------------------------------------------------------------------
// Configuration resolution
// ---------------------------------------------------------------------------

func TestResolveConfigUsesEnvironmentAndDefaultAuthority(t *testing.T) {
	cfg, err := resolveWorkloadIdentityConfig("", "", envFrom(map[string]string{
		"AZURE_TENANT_ID":            testTenantID,
		"AZURE_CLIENT_ID":            testClientID,
		"AZURE_FEDERATED_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := workloadIdentityConfig{
		authorityHost: "https://login.microsoftonline.com",
		tenantID:      testTenantID,
		clientID:      testClientID,
		tokenFile:     "/var/run/secrets/azure/tokens/azure-identity-token",
	}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
	if got := cfg.tokenEndpoint(); got != "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token" {
		t.Fatalf("token endpoint = %q", got)
	}
}

func TestResolveConfigParamsOverrideEnvironment(t *testing.T) {
	cfg, err := resolveWorkloadIdentityConfig(
		"99999999-8888-7777-6666-555555555555",
		"contoso.onmicrosoft.com",
		envFrom(map[string]string{
			"AZURE_TENANT_ID":            testTenantID,
			"AZURE_CLIENT_ID":            testClientID,
			"AZURE_FEDERATED_TOKEN_FILE": "/token",
		}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.clientID != "99999999-8888-7777-6666-555555555555" || cfg.tenantID != "contoso.onmicrosoft.com" {
		t.Fatalf("params did not override env: %+v", cfg)
	}
}

func TestResolveConfigReadsSovereignCloudAuthorityHost(t *testing.T) {
	cfg, err := resolveWorkloadIdentityConfig("", "", envFrom(map[string]string{
		"AZURE_TENANT_ID":            testTenantID,
		"AZURE_CLIENT_ID":            testClientID,
		"AZURE_FEDERATED_TOKEN_FILE": "/token",
		"AZURE_AUTHORITY_HOST":       "https://login.chinacloudapi.cn/",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.tokenEndpoint(); got != "https://login.chinacloudapi.cn/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token" {
		t.Fatalf("token endpoint = %q", got)
	}
}

func TestResolveConfigRejectsUnusableConfiguration(t *testing.T) {
	base := map[string]string{
		"AZURE_TENANT_ID":            testTenantID,
		"AZURE_CLIENT_ID":            testClientID,
		"AZURE_FEDERATED_TOKEN_FILE": "/token",
	}
	with := func(key, value string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		if value == "" {
			delete(m, key)
		} else {
			m[key] = value
		}
		return m
	}

	tests := []struct {
		name        string
		clientParam string
		tenantParam string
		env         map[string]string
		wantInError string
	}{
		{name: "no tenant anywhere", env: with("AZURE_TENANT_ID", ""), wantInError: "AZURE_TENANT_ID"},
		{name: "no client anywhere", env: with("AZURE_CLIENT_ID", ""), wantInError: "AZURE_CLIENT_ID"},
		{name: "no federated token file", env: with("AZURE_FEDERATED_TOKEN_FILE", ""), wantInError: "AZURE_FEDERATED_TOKEN_FILE"},
		{name: "plain http authority", env: with("AZURE_AUTHORITY_HOST", "http://login.microsoftonline.com/"), wantInError: "https"},
		{name: "authority with credentials", env: with("AZURE_AUTHORITY_HOST", "https://user:pass@login.microsoftonline.com/"), wantInError: "AZURE_AUTHORITY_HOST"},
		{name: "authority with query", env: with("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com/?x=1"), wantInError: "AZURE_AUTHORITY_HOST"},
		{name: "authority without host", env: with("AZURE_AUTHORITY_HOST", "https:///"), wantInError: "AZURE_AUTHORITY_HOST"},
		{name: "tenant param with path characters", tenantParam: "../../evil", env: base, wantInError: "tenantId"},
		{name: "tenant env with path characters", env: with("AZURE_TENANT_ID", "a/b"), wantInError: "AZURE_TENANT_ID"},
		{name: "client param not a GUID", clientParam: "my-app", env: base, wantInError: "clientId"},
		{name: "client env not a GUID", env: with("AZURE_CLIENT_ID", "1234"), wantInError: "AZURE_CLIENT_ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveWorkloadIdentityConfig(tt.clientParam, tt.tenantParam, envFrom(tt.env))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantInError) {
				t.Fatalf("error %q does not mention %q", err, tt.wantInError)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Token requests against a fake Entra ID token endpoint
// ---------------------------------------------------------------------------

type entraRequest struct {
	method      string
	path        string
	contentType string
	form        url.Values
}

type fakeEntra struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []entraRequest
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

func newFakeEntra(t *testing.T, respond func(n int, w http.ResponseWriter, r *http.Request)) *fakeEntra {
	t.Helper()
	f := &fakeEntra{respond: respond}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.reqs = append(f.reqs, entraRequest{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			form:        r.PostForm,
		})
		n := len(f.reqs)
		f.mu.Unlock()
		f.respond(n, w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEntra) requests() []entraRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]entraRequest(nil), f.reqs...)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func tokenResponse(accessToken string, expiresIn any) map[string]any {
	return map[string]any{"token_type": "Bearer", "expires_in": expiresIn, "ext_expires_in": expiresIn, "access_token": accessToken}
}

func writeAssertion(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type recordedSleeps struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (r *recordedSleeps) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delays = append(r.delays, d)
	return nil
}

func newTestClient(f *fakeEntra, tokenFile string) (*tokenClient, *recordedSleeps) {
	cfg := workloadIdentityConfig{
		authorityHost: f.srv.URL,
		tenantID:      testTenantID,
		clientID:      testClientID,
		tokenFile:     tokenFile,
	}
	c := newTokenClient(cfg, f.srv.Client().Transport)
	c.now = func() time.Time { return fixedNow }
	sleeps := &recordedSleeps{}
	c.sleep = sleeps.sleep
	return c, sleeps
}

func TestFetchTokenSendsWorkloadIdentityRequest(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok-1", 3599))
	})
	c, _ := newTestClient(f, writeAssertion(t, "federated-jwt"))

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost {
		t.Errorf("method = %s", r.method)
	}
	if r.path != "/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token" {
		t.Errorf("path = %s", r.path)
	}
	if r.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %s", r.contentType)
	}
	wantForm := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {testClientID},
		"scope":                 {"https://ai.azure.com/.default"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {"federated-jwt"},
	}
	if r.form.Encode() != wantForm.Encode() {
		t.Errorf("form = %s\nwant  %s", r.form.Encode(), wantForm.Encode())
	}

	if tok.value != "tok-1" {
		t.Errorf("token = %q", tok.value)
	}
	if want := fixedNow.Add(3599 * time.Second); !tok.expiresOn.Equal(want) {
		t.Errorf("expiresOn = %v, want %v", tok.expiresOn, want)
	}
	if want := fixedNow.Add(3599*time.Second - 5*time.Minute); !tok.refreshAt.Equal(want) {
		t.Errorf("refreshAt = %v, want %v", tok.refreshAt, want)
	}
}

func TestFetchTokenAcceptsStringExpiresIn(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok", "3600"))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := fixedNow.Add(time.Hour); !tok.expiresOn.Equal(want) {
		t.Fatalf("expiresOn = %v, want %v", tok.expiresOn, want)
	}
}

func TestFetchTokenUsesRefreshInHint(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		body := tokenResponse("tok", 86399)
		body["refresh_in"] = 43199
		writeJSON(w, http.StatusOK, body)
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := fixedNow.Add(43199 * time.Second); !tok.refreshAt.Equal(want) {
		t.Fatalf("refreshAt = %v, want %v", tok.refreshAt, want)
	}
}

func TestFetchTokenRefreshesShortLivedTokenAtHalfLife(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok", 300))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := fixedNow.Add(150 * time.Second); !tok.refreshAt.Equal(want) {
		t.Fatalf("refreshAt = %v, want %v", tok.refreshAt, want)
	}
}

func TestFetchTokenRereadsFederatedTokenOnEveryFetch(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	path := writeAssertion(t, "assertion-1")
	c, _ := newTestClient(f, path)

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("assertion-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatal(err)
	}

	reqs := f.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	if got := reqs[0].form.Get("client_assertion"); got != "assertion-1" {
		t.Errorf("first assertion = %q", got)
	}
	if got := reqs[1].form.Get("client_assertion"); got != "assertion-2" {
		t.Errorf("second assertion = %q", got)
	}
}

func TestFetchTokenTrimsFederatedToken(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	c, _ := newTestClient(f, writeAssertion(t, "  jwt-value\n"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatal(err)
	}
	if got := f.requests()[0].form.Get("client_assertion"); got != "jwt-value" {
		t.Fatalf("assertion = %q, want %q", got, "jwt-value")
	}
}

func TestFetchTokenRejectsUnusableFederatedToken(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{name: "empty file", path: func(t *testing.T) string { return writeAssertion(t, " \n") }},
		{name: "missing file", path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") }},
		{name: "oversized file", path: func(t *testing.T) string { return writeAssertion(t, strings.Repeat("a", 64*1024+1)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
			})
			c, _ := newTestClient(f, tt.path(t))

			_, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
			if err == nil {
				t.Fatal("expected an error")
			}
			if n := len(f.requests()); n != 0 {
				t.Fatalf("token endpoint called %d times, want 0", n)
			}
		})
	}
}

func TestFetchTokenRejectsInvalidSuccessResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing access_token", body: `{"token_type":"Bearer","expires_in":3600}`},
		{name: "missing expires_in", body: `{"token_type":"Bearer","access_token":"tok"}`},
		{name: "zero expires_in", body: `{"token_type":"Bearer","expires_in":0,"access_token":"tok"}`},
		{name: "non-numeric expires_in", body: `{"token_type":"Bearer","expires_in":"soon","access_token":"tok"}`},
		{name: "not a bearer token", body: `{"token_type":"pop","expires_in":3600,"access_token":"tok"}`},
		{name: "not JSON", body: `<html>proxy error</html>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			})
			c, _ := newTestClient(f, writeAssertion(t, "jwt"))

			if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
				t.Fatal("expected an error")
			}
			if n := len(f.requests()); n != 1 {
				t.Fatalf("requests = %d, want 1 (no retry)", n)
			}
		})
	}
}

func TestFetchTokenDoesNotRetryRejectedRequest(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, status, map[string]any{
					"error":             "invalid_client",
					"error_description": "AADSTS700016: Application with identifier was not found in the directory.",
					"error_codes":       []int{700016},
					"correlation_id":    "corr-1",
					"trace_id":          "trace-1",
				})
			})
			c, _ := newTestClient(f, writeAssertion(t, "secret-federated-jwt"))

			_, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
			if err == nil {
				t.Fatal("expected an error")
			}
			if n := len(f.requests()); n != 1 {
				t.Fatalf("requests = %d, want 1", n)
			}
			msg := err.Error()
			for _, want := range []string{"invalid_client", "700016", "corr-1"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
			if strings.Contains(msg, "secret-federated-jwt") {
				t.Errorf("error leaks the federated token: %q", msg)
			}
		})
	}
}

func TestFetchTokenRetriesThrottledRequestHonouringRetryAfter(t *testing.T) {
	f := newFakeEntra(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "3")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "temporarily_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	c, sleeps := newTestClient(f, writeAssertion(t, "jwt"))

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.value != "tok" {
		t.Fatalf("token = %q", tok.value)
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
	if len(sleeps.delays) != 1 || sleeps.delays[0] < 3*time.Second {
		t.Fatalf("sleeps = %v, want one sleep of at least 3s", sleeps.delays)
	}
}

func TestFetchTokenRetriesServerError(t *testing.T) {
	f := newFakeEntra(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}

func TestFetchTokenGivesUpAfterTwoRetries(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error")
	}
	if n := len(f.requests()); n != 3 {
		t.Fatalf("requests = %d, want 3", n)
	}
}

func TestFetchTokenRetriesDroppedConnection(t *testing.T) {
	f := newFakeEntra(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
}

func TestFetchTokenDoesNotFollowRedirects(t *testing.T) {
	var f *fakeEntra
	f = newFakeEntra(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
			return
		}
		w.Header().Set("Location", f.srv.URL+"/elsewhere")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error")
	}
	for _, r := range f.requests() {
		if r.path == "/elsewhere" {
			t.Fatal("the redirect was followed, sending the federated token to another URL")
		}
	}
}

func TestFetchTokenRejectsOversizedResponse(t *testing.T) {
	// A valid token followed by padding: truncating at 1 MiB would still parse, so only an
	// explicit size check rejects it.
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600,"access_token":"tok"}`))
		_, _ = w.Write([]byte(strings.Repeat(" ", 1<<20)))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestFetchTokenStopsAtDeadline(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		writeJSON(w, http.StatusOK, tokenResponse("tok", 3600))
	})
	c, _ := newTestClient(f, writeAssertion(t, "jwt"))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.fetchToken(ctx, "https://ai.azure.com/.default")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v is not a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("fetch took %v after a 100ms deadline", elapsed)
	}
}

func TestFetchTokenDoesNotWaitPastDeadlineForRetryAfter(t *testing.T) {
	f := newFakeEntra(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "temporarily_unavailable"})
	})
	c, sleeps := newTestClient(f, writeAssertion(t, "jwt"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.fetchToken(ctx, "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error")
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	if len(sleeps.delays) != 0 {
		t.Fatalf("slept %v although Retry-After exceeds the deadline", sleeps.delays)
	}
}
