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
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	// expiryMargin is how much validity a cached token must have left to be sent upstream, so a
	// request never leaves the gateway with a token about to expire in flight.
	expiryMargin = time.Minute

	// backgroundRetryInterval is how long to wait after a failed background refresh before the
	// next one. The cached token stays in use meanwhile.
	backgroundRetryInterval = 30 * time.Second

	// rejectionCacheFor is how long a rejected token request (see isRejection) is returned to
	// callers without a new request, give or take a quarter for jitter. It keeps a misconfigured
	// identity from sending Entra ID or the host's IMDS a token request for every API request.
	rejectionCacheFor = 2 * time.Second
)

// tokenSource caches one access token for one identity and scope, and refreshes it.
//
//   - fresh (now < refreshAt): the cached token is returned with no network call;
//   - due (refreshAt <= now < expiresOn - expiryMargin): the cached token is returned and one
//     background refresh is started, unless one is running or the last one failed less than
//     backgroundRetryInterval ago;
//   - missing or expired: the caller waits for a fetch, shared with every other caller.
//
// Every fetch runs on its own context bounded by timeout, so a cancelled request never aborts a
// fetch other requests are waiting on. A rejected fetch is returned to callers for about
// rejectionCacheFor without a new fetch; any other failure is not cached.
type tokenSource struct {
	fetcher  tokenFetcher
	scope    string
	timeout  time.Duration
	logAttrs []any
	now      func() time.Time

	mu                    sync.Mutex
	tok                   *accessToken
	inFlight              *fetchCall
	nextBackgroundAttempt time.Time
	rejection             error
	rejectionUntil        time.Time
}

// cachedFailure is a recent rejection returned again without a new token request. It unwraps to
// the rejection, so its fault reason is the same.
type cachedFailure struct{ err error }

func (c *cachedFailure) Error() string { return c.err.Error() }
func (c *cachedFailure) Unwrap() error { return c.err }

// isRejection reports whether err is a token endpoint refusing the request itself: a 4xx answer
// that is not throttling, such as invalid_client or IMDS's "Identity not found". Only a
// configuration change clears it, so it is worth caching; anything else may clear on its own.
func isRejection(err error) bool {
	var e *tokenRequestError
	return errors.As(err, &e) && e.kind == errKindEndpoint && !e.retryable && e.status >= 400 && e.status < 500
}

// fetchCall is one fetch, shared by every caller that arrives while it runs.
type fetchCall struct {
	done chan struct{}
	tok  *accessToken
	err  error
}

func newTokenSource(fetcher tokenFetcher, scope string, timeout time.Duration, logAttrs []any) *tokenSource {
	return &tokenSource{
		fetcher:  fetcher,
		scope:    scope,
		timeout:  timeout,
		logAttrs: logAttrs,
		now:      time.Now,
	}
}

// Token returns a usable access token.
func (s *tokenSource) Token(ctx context.Context) (*accessToken, error) {
	s.mu.Lock()
	now := s.now()
	if tok := s.tok; tok != nil && now.Before(tok.expiresOn.Add(-expiryMargin)) {
		if !now.Before(tok.refreshAt) && s.inFlight == nil && !now.Before(s.nextBackgroundAttempt) {
			s.startFetchLocked(true)
		}
		s.mu.Unlock()
		return tok, nil
	}
	if s.rejection != nil && now.Before(s.rejectionUntil) {
		err := &cachedFailure{err: s.rejection}
		s.mu.Unlock()
		return nil, err
	}
	call := s.inFlight
	if call == nil {
		call = s.startFetchLocked(false)
	}
	s.mu.Unlock()

	select {
	case <-call.done:
		return call.tok, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startFetchLocked starts a fetch in its own goroutine. s.mu must be held.
func (s *tokenSource) startFetchLocked(background bool) *fetchCall {
	call := &fetchCall{done: make(chan struct{})}
	s.inFlight = call
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		tok, err := s.fetcher.fetchToken(ctx, s.scope)
		call.tok, call.err = tok, err

		s.mu.Lock()
		s.inFlight = nil
		switch {
		case err == nil:
			s.tok = tok
			s.nextBackgroundAttempt = time.Time{}
			s.rejection = nil
		case background:
			s.nextBackgroundAttempt = s.now().Add(backgroundRetryInterval)
		case isRejection(err):
			s.rejection = err
			s.rejectionUntil = s.now().Add(rejectionCacheFor*3/4 + rand.N(rejectionCacheFor/2+1))
		}
		s.mu.Unlock()
		close(call.done)

		if err != nil && background {
			slog.Warn("AzureAuthentication: background token refresh failed; the cached token stays in use",
				append([]any{"error", err}, s.logAttrs...)...)
		}
	}()
	return call
}

// sourceKey identifies a shared token source: the same identity, scope and timeout always map to
// the same cached token, across routes and across config pushes that rebuild policy instances.
type sourceKey struct {
	identity identityConfig
	scope    string
	timeout  time.Duration
}

// sourceRegistry is the process-wide set of token sources.
type sourceRegistry struct {
	mu      sync.Mutex
	sources map[sourceKey]*tokenSource
}

func newSourceRegistry() *sourceRegistry {
	return &sourceRegistry{sources: make(map[sourceKey]*tokenSource)}
}

// get returns the source for key, calling build to create it the first time.
func (r *sourceRegistry) get(key sourceKey, build func() *tokenSource) *tokenSource {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sources[key]; ok {
		return s
	}
	s := build()
	r.sources[key] = s
	return s
}
