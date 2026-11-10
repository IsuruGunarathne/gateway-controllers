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
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeFetcher stands in for the token endpoint. Each call runs respond with the 1-based call
// number; respond may block to simulate a slow endpoint.
type fakeFetcher struct {
	mu        sync.Mutex
	calls     int
	scopes    []string
	deadlines []time.Time
	respond   func(ctx context.Context, call int) (*accessToken, error)
}

func (f *fakeFetcher) fetchToken(ctx context.Context, scope string) (*accessToken, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.scopes = append(f.scopes, scope)
	if d, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, d)
	}
	f.mu.Unlock()
	return f.respond(ctx, n)
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// testClock is a settable clock for the token source.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// hourToken expires an hour after issue and is due for refresh five minutes before that.
func hourToken(value string, issuedAt time.Time) *accessToken {
	return &accessToken{value: value, expiresOn: issuedAt.Add(time.Hour), refreshAt: issuedAt.Add(55 * time.Minute)}
}

func newTestSource(f tokenFetcher, clock *testClock) *tokenSource {
	s := newTokenSource(f, "https://ai.azure.com/.default", 10*time.Second, nil)
	s.now = clock.Now
	return s
}

// waitForIdle blocks until the source has no fetch in flight.
func waitForIdle(t *testing.T, s *tokenSource) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		idle := s.inFlight == nil
		s.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("token source still fetching after 2s")
}

func mustToken(t *testing.T, s *tokenSource) string {
	t.Helper()
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return tok.value
}

func TestTokenSourceServesFreshTokenWithoutFetching(t *testing.T) {
	clock := &testClock{now: fixedNow}
	f := &fakeFetcher{respond: func(_ context.Context, n int) (*accessToken, error) {
		return hourToken("tok-1", fixedNow), nil
	}}
	s := newTestSource(f, clock)

	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	clock.Set(fixedNow.Add(30 * time.Minute))
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	if f.scopes[0] != "https://ai.azure.com/.default" {
		t.Fatalf("scope = %q", f.scopes[0])
	}
}

func TestTokenSourceRefreshesInBackgroundWhenDue(t *testing.T) {
	clock := &testClock{now: fixedNow}
	release := make(chan struct{})
	f := &fakeFetcher{respond: func(_ context.Context, n int) (*accessToken, error) {
		if n == 1 {
			return hourToken("tok-1", fixedNow), nil
		}
		<-release
		return hourToken("tok-2", fixedNow.Add(56*time.Minute)), nil
	}}
	s := newTestSource(f, clock)
	mustToken(t, s)

	clock.Set(fixedNow.Add(56 * time.Minute)) // past refreshAt, before expiry
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token while refresh is running = %q, want the cached tok-1", got)
	}
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	close(release)
	waitForIdle(t, s)

	if got := mustToken(t, s); got != "tok-2" {
		t.Fatalf("token after refresh = %q, want tok-2", got)
	}
	if n := f.callCount(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (one initial, one background)", n)
	}
}

func TestTokenSourceKeepsTokenWhenBackgroundRefreshFails(t *testing.T) {
	clock := &testClock{now: fixedNow}
	f := &fakeFetcher{respond: func(_ context.Context, n int) (*accessToken, error) {
		if n == 1 {
			return hourToken("tok-1", fixedNow), nil
		}
		return nil, errors.New("entra unavailable")
	}}
	s := newTestSource(f, clock)
	mustToken(t, s)

	clock.Set(fixedNow.Add(56 * time.Minute))
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	waitForIdle(t, s)

	// The failed refresh must not be retried on every request.
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token after failed refresh = %q, want tok-1", got)
	}
	waitForIdle(t, s)
	if n := f.callCount(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (no retry straight after a failed refresh)", n)
	}

	// Once the retry interval has passed, the next request tries again.
	clock.Set(fixedNow.Add(56*time.Minute + 31*time.Second))
	mustToken(t, s)
	waitForIdle(t, s)
	if n := f.callCount(); n != 3 {
		t.Fatalf("fetches = %d, want 3", n)
	}
}

func TestTokenSourceFetchesSynchronouslyWhenTokenExpires(t *testing.T) {
	clock := &testClock{now: fixedNow}
	f := &fakeFetcher{respond: func(_ context.Context, n int) (*accessToken, error) {
		if n == 1 {
			return hourToken("tok-1", fixedNow), nil
		}
		return hourToken("tok-2", fixedNow.Add(59*time.Minute+30*time.Second)), nil
	}}
	s := newTestSource(f, clock)
	mustToken(t, s)

	clock.Set(fixedNow.Add(59*time.Minute + 30*time.Second)) // less than a minute of validity left
	if got := mustToken(t, s); got != "tok-2" {
		t.Fatalf("token = %q, want a fresh tok-2", got)
	}
}

func TestTokenSourceSharesOneFetchAmongConcurrentCallers(t *testing.T) {
	clock := &testClock{now: fixedNow}
	release := make(chan struct{})
	f := &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
		<-release
		return hourToken("tok-1", fixedNow), nil
	}}
	s := newTestSource(f, clock)

	const callers = 20
	var wg sync.WaitGroup
	results := make(chan string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := s.Token(context.Background())
			if err != nil {
				results <- "error: " + err.Error()
				return
			}
			results <- tok.value
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for got := range results {
		if got != "tok-1" {
			t.Fatalf("caller got %q", got)
		}
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestTokenSourceDoesNotCacheFailures(t *testing.T) {
	clock := &testClock{now: fixedNow}
	f := &fakeFetcher{respond: func(_ context.Context, n int) (*accessToken, error) {
		if n == 1 {
			return nil, errors.New("entra unavailable")
		}
		return hourToken("tok-1", fixedNow), nil
	}}
	s := newTestSource(f, clock)

	if _, err := s.Token(context.Background()); err == nil {
		t.Fatal("expected the first fetch's error")
	}
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	if n := f.callCount(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestTokenSourceWaiterHonoursItsOwnContext(t *testing.T) {
	clock := &testClock{now: fixedNow}
	release := make(chan struct{})
	f := &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
		<-release
		return hourToken("tok-1", fixedNow), nil
	}}
	s := newTestSource(f, clock)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := s.Token(ctx)
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled caller still waiting")
	}

	// The shared fetch carries on and its token serves later requests.
	close(release)
	waitForIdle(t, s)
	if got := mustToken(t, s); got != "tok-1" {
		t.Fatalf("token = %q", got)
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestTokenSourceBoundsEachFetchWithItsTimeout(t *testing.T) {
	clock := &testClock{now: fixedNow}
	f := &fakeFetcher{respond: func(_ context.Context, _ int) (*accessToken, error) {
		return hourToken("tok-1", fixedNow), nil
	}}
	s := newTestSource(f, clock)

	before := time.Now()
	mustToken(t, s)
	if len(f.deadlines) != 1 {
		t.Fatal("fetch ran without a deadline")
	}
	if d := f.deadlines[0].Sub(before); d <= 0 || d > 10*time.Second+time.Second {
		t.Fatalf("fetch deadline %v after start, want about 10s", d)
	}
}

func TestSourceRegistryReusesSourcePerKey(t *testing.T) {
	r := newSourceRegistry()
	builds := 0
	build := func() *tokenSource {
		builds++
		return newTokenSource(&fakeFetcher{}, "s", time.Second, nil)
	}
	cfg := workloadIdentityConfig{authorityHost: defaultAuthorityHost, tenantID: testTenantID, clientID: testClientID, tokenFile: "/t"}

	a := r.get(sourceKey{cfg: cfg, scope: "https://ai.azure.com/.default", timeout: 10 * time.Second}, build)
	b := r.get(sourceKey{cfg: cfg, scope: "https://ai.azure.com/.default", timeout: 10 * time.Second}, build)
	if a != b || builds != 1 {
		t.Fatalf("same key built %d sources", builds)
	}

	otherScope := r.get(sourceKey{cfg: cfg, scope: "https://cognitiveservices.azure.com/.default", timeout: 10 * time.Second}, build)
	otherCfg := cfg
	otherCfg.clientID = "99999999-8888-7777-6666-555555555555"
	otherClient := r.get(sourceKey{cfg: otherCfg, scope: "https://ai.azure.com/.default", timeout: 10 * time.Second}, build)
	if otherScope == a || otherClient == a || otherScope == otherClient || builds != 3 {
		t.Fatalf("distinct keys must get distinct sources (builds = %d)", builds)
	}
}
