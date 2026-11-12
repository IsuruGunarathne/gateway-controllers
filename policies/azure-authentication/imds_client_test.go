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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration resolution
// ---------------------------------------------------------------------------

func TestResolveManagedIdentityConfig(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		env      map[string]string
		want     managedIdentityConfig
	}{
		{
			name: "system-assigned identity at the IMDS address",
			want: managedIdentityConfig{endpoint: imdsTokenEndpoint},
		},
		{
			name:     "user-assigned identity from the clientId param",
			clientID: testClientID,
			want:     managedIdentityConfig{endpoint: imdsTokenEndpoint, clientID: testClientID},
		},
		{
			name: "AZURE_CLIENT_ID from Workload Identity is not used",
			env:  map[string]string{"AZURE_CLIENT_ID": "99999999-8888-7777-6666-555555555555"},
			want: managedIdentityConfig{endpoint: imdsTokenEndpoint},
		},
		{
			name: "https endpoint override",
			env:  map[string]string{"AZURE_IMDS_TOKEN_ENDPOINT": "https://testbench:3028/imds/metadata/identity/oauth2/token"},
			want: managedIdentityConfig{endpoint: "https://testbench:3028/imds/metadata/identity/oauth2/token"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveManagedIdentityConfig(tt.clientID, envFrom(tt.env))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("config = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolveManagedIdentityConfigRejectsUnusableConfiguration(t *testing.T) {
	const overrideError = "the AZURE_IMDS_TOKEN_ENDPOINT environment variable must be an https URL with a host and no credentials, query or fragment"
	tests := []struct {
		name        string
		clientID    string
		override    string
		wantInError string
	}{
		{name: "clientId not a GUID", clientID: "my-app", wantInError: "'clientId' must be an application (client) ID in GUID form"},
		{name: "plain http override", override: "http://evil:80/t", wantInError: overrideError},
		{name: "override with credentials", override: "https://u:p@h/t", wantInError: overrideError},
		{name: "override with a query", override: "https://h/t?x=1", wantInError: overrideError},
		{name: "override with a fragment", override: "https://h/t#f", wantInError: overrideError},
		{name: "override without a host", override: "https:///t", wantInError: overrideError},
		{name: "unparsable override", override: "::", wantInError: overrideError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveManagedIdentityConfig(tt.clientID, envFrom(map[string]string{"AZURE_IMDS_TOKEN_ENDPOINT": tt.override}))
			if err == nil || !strings.Contains(err.Error(), tt.wantInError) {
				t.Fatalf("error = %v, want one containing %q", err, tt.wantInError)
			}
		})
	}
}

func TestResourceFromScope(t *testing.T) {
	tests := map[string]string{
		"https://ai.azure.com/.default":                       "https://ai.azure.com",
		"https://cognitiveservices.azure.com/.default":        "https://cognitiveservices.azure.com",
		"api://11111111-2222-3333-4444-555555555555/.default": "api://11111111-2222-3333-4444-555555555555",
	}
	for scope, want := range tests {
		if got := resourceFromScope(scope); got != want {
			t.Errorf("resourceFromScope(%q) = %q, want %q", scope, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Token requests against a fake IMDS
// ---------------------------------------------------------------------------

type imdsRequest struct {
	method       string
	path         string
	query        url.Values
	metadata     string
	forwardedFor string
	bodyLen      int64
}

type fakeIMDS struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []imdsRequest
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

func newFakeIMDS(t *testing.T, respond func(n int, w http.ResponseWriter, r *http.Request)) *fakeIMDS {
	t.Helper()
	f := &fakeIMDS{respond: respond}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, imdsRequest{
			method:       r.Method,
			path:         r.URL.Path,
			query:        r.URL.Query(),
			metadata:     r.Header.Get("Metadata"),
			forwardedFor: r.Header.Get("X-Forwarded-For"),
			bodyLen:      n,
		})
		count := len(f.reqs)
		f.mu.Unlock()
		f.respond(count, w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIMDS) requests() []imdsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]imdsRequest(nil), f.reqs...)
}

func newTestIMDSClient(f *fakeIMDS, clientID string) (*imdsClient, *recordedSleeps) {
	cfg := managedIdentityConfig{endpoint: f.srv.URL + "/metadata/identity/oauth2/token", clientID: clientID}
	c := newIMDSClient(cfg, f.srv.Client().Transport)
	c.now = func() time.Time { return fixedNow }
	sleeps := &recordedSleeps{}
	c.sleep = sleeps.sleep
	return c, sleeps
}

func okIMDS(_ int, w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, tokenResponse("tok-imds", "3599"))
}

func TestIMDSFetchSendsManagedIdentityRequest(t *testing.T) {
	f := newFakeIMDS(t, okIMDS)
	c, _ := newTestIMDSClient(f, testClientID)

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if tok.value != "tok-imds" {
		t.Fatalf("token = %q, want tok-imds", tok.value)
	}
	if want := fixedNow.Add(3599 * time.Second); !tok.expiresOn.Equal(want) {
		t.Fatalf("expiresOn = %v, want %v", tok.expiresOn, want)
	}

	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodGet || r.path != "/metadata/identity/oauth2/token" {
		t.Fatalf("request = %s %s, want GET /metadata/identity/oauth2/token", r.method, r.path)
	}
	for key, want := range map[string]string{
		"api-version": "2018-02-01",
		"resource":    "https://ai.azure.com",
		"client_id":   testClientID,
	} {
		if got := r.query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if r.metadata != "true" {
		t.Errorf("Metadata header = %q, want true", r.metadata)
	}
	if r.forwardedFor != "" {
		t.Errorf("X-Forwarded-For = %q, want none", r.forwardedFor)
	}
	if r.bodyLen != 0 {
		t.Errorf("body length = %d, want 0", r.bodyLen)
	}
}

func TestIMDSFetchOmitsClientIDForSystemAssignedIdentity(t *testing.T) {
	f := newFakeIMDS(t, okIMDS)
	c, _ := newTestIMDSClient(f, "")

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if _, ok := f.requests()[0].query["client_id"]; ok {
		t.Fatal("a system-assigned request must not carry client_id")
	}
}

func TestIMDSFetchRetriesTransientStatuses(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newFakeIMDS(t, func(n int, w http.ResponseWriter, r *http.Request) {
				if n == 1 {
					w.WriteHeader(status)
					return
				}
				okIMDS(n, w, r)
			})
			c, sleeps := newTestIMDSClient(f, testClientID)

			tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
			if err != nil || tok.value != "tok-imds" {
				t.Fatalf("fetchToken = %v, %v; want the token after one retry", tok, err)
			}
			if n := len(f.requests()); n != 2 {
				t.Fatalf("requests = %d, want 2", n)
			}
			if n := len(sleeps.delays); n != 1 {
				t.Fatalf("delays = %d, want 1", n)
			}
		})
	}
}

func TestIMDSFetchDoesNotRetryBadRequest(t *testing.T) {
	f := newFakeIMDS(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Identity not found"})
	})
	c, _ := newTestIMDSClient(f, testClientID)

	_, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	var e *tokenRequestError
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want a *tokenRequestError", err)
	}
	if e.kind != errKindEndpoint || e.status != http.StatusBadRequest || e.code != "invalid_request" ||
		e.description != "Identity not found" || e.retryable {
		t.Fatalf("error = %+v, want a non-retryable 400 invalid_request \"Identity not found\"", e)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1 (a 400 is not retried)", n)
	}
}

func TestIMDSFetchGivesUpAfterFourRetries(t *testing.T) {
	f := newFakeIMDS(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c, sleeps := newTestIMDSClient(f, testClientID)

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error")
	}
	if n := len(f.requests()); n != 5 {
		t.Fatalf("requests = %d, want 5", n)
	}
	if n := len(sleeps.delays); n != 4 {
		t.Fatalf("delays = %d, want 4", n)
	}
}

func TestIMDSFetchHonoursRetryAfter(t *testing.T) {
	f := newFakeIMDS(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		okIMDS(n, w, r)
	})
	c, sleeps := newTestIMDSClient(f, testClientID)

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if len(sleeps.delays) != 1 || sleeps.delays[0] != 3*time.Second {
		t.Fatalf("delays = %v, want [3s]", sleeps.delays)
	}
}

func TestIMDSFetchRefreshesNearExpiryTokenAtHalfLife(t *testing.T) {
	f := newFakeIMDS(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, tokenResponse("tok-cached", "240"))
	})
	c, _ := newTestIMDSClient(f, testClientID)

	tok, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default")
	if err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if want := fixedNow.Add(120 * time.Second); !tok.refreshAt.Equal(want) {
		t.Fatalf("refreshAt = %v, want %v (half the remaining life)", tok.refreshAt, want)
	}
}

func TestIMDSFetchDoesNotFollowRedirects(t *testing.T) {
	elsewhere := newFakeIMDS(t, okIMDS)
	f := newFakeIMDS(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL+"/metadata/identity/oauth2/token", http.StatusFound)
	})
	c, _ := newTestIMDSClient(f, testClientID)

	if _, err := c.fetchToken(context.Background(), "https://ai.azure.com/.default"); err == nil {
		t.Fatal("expected an error for a redirect")
	}
	if n := len(elsewhere.requests()); n != 0 {
		t.Fatalf("the redirect target got %d requests, want 0", n)
	}
}

func TestIMDSTransportNeverUsesAProxy(t *testing.T) {
	tr := imdsTransport()
	if tr.Proxy != nil {
		t.Fatal("the IMDS transport must not use a proxy")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("the IMDS transport must require TLS 1.2 or newer for an https override")
	}
	if tr == sharedTransport() {
		t.Fatal("the IMDS transport must not be the Entra transport, which honours proxy settings")
	}
	if imdsTransport() != tr {
		t.Fatal("the IMDS transport must be one process-wide instance")
	}
}
