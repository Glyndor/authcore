package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The four tests in this file pin down the trust bounds on the JWKS cache:
// a cached key set is refused once it has crossed its expiry and a refresh
// cannot succeed; an authoritative empty key set replaces the cache; and a
// cold-cache fetch must not lose concurrent callers or be poisoned by a
// caller-cancelled first attempt.

// jwksDocFor builds a JWKS document carrying a single RSA key under the
// given kid, taken from the public half of key.
func jwksDocFor(pub *rsa.PublicKey, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

// newCache builds a cache backed by srv, with a controllable clock.
// The clock starts at the zero value so the first refresh records an expiry
// in the future; the test then advances it as needed.
func newCache(srv *httptest.Server, fakeNow time.Time) *jwksCache {
	c := newJWKSCache(srv.URL, srv.Client())
	c.now = func() time.Time { return fakeNow }
	return c
}

// waitFor receives from ch, or fails the test if the control under test has
// regressed and nothing ever arrives. Without the bound, a broken cooldown
// rule turns a red test into a hung package.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		var zero T
		t.Fatalf("timed out waiting for %s", what)
		return zero
	}
}

func mustGenRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return k
}

// TestJWKS_failsClosedAfterExpiry pins down the fail-closed contract: once the
// cached set has crossed its TTL, a failed refresh must surface ErrJWKSStale
// rather than serving the withdrawn key. The acceptance pair verifies a
// successful refresh in the same situation still returns the rotated key.
func TestJWKS_failsClosedAfterExpiry(t *testing.T) {
	old := mustGenRSA(t)
	newer := mustGenRSA(t)
	const kid = "rotating"

	var serve500 atomic.Bool
	var doc atomic.Value // string
	doc.Store(jwksDocFor(&old.PublicKey, kid))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if serve500.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(doc.Load().(string)))
	}))
	defer srv.Close()

	clock := time.Unix(1_700_000_000, 0)
	cache := newCache(srv, clock)

	// Prime the cache: a normal refresh populates keys and bumps expiresAt.
	if _, err := cache.key(context.Background(), kid, "RS256"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Advance the clock past the TTL.
	cache.now = func() time.Time { return clock.Add(jwksTTL + time.Second) }

	t.Run("rejected when refresh fails", func(t *testing.T) {
		serve500.Store(true)
		defer serve500.Store(false)

		_, err := cache.key(context.Background(), kid, "RS256")
		if err == nil {
			t.Fatal("a lookup past expiry with a failing refresh must not return a key")
		}
		if !errors.Is(err, ErrJWKSStale) {
			t.Fatalf("err = %v, want errors.Is(..., ErrJWKSStale)", err)
		}
	})

	t.Run("accepted when refresh succeeds", func(t *testing.T) {
		doc.Store(jwksDocFor(&newer.PublicKey, kid))
		// The failed refresh above starts a cooldown during which a stale
		// kid fails closed without fetching; step past it.
		cache.now = func() time.Time { return clock.Add(jwksTTL + time.Second + minRefreshInterval) }

		got, err := cache.key(context.Background(), kid, "RS256")
		if err != nil {
			t.Fatalf("key after a successful refresh: %v", err)
		}
		pub, ok := got.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("returned key type = %T, want *rsa.PublicKey", got)
		}
		if pub.N.Cmp(newer.PublicKey.N) != 0 {
			t.Fatal("the returned key is not the rotated material")
		}
	})
}

// TestJWKS_emptySetRemovesCachedKeys: a 200 OK with {"keys":[]} is the
// provider saying the keys are gone. The cache must replace the entry rather
// than keep the previous set, so lookups for the now-removed kid fail.
func TestJWKS_emptySetRemovesCachedKeys(t *testing.T) {
	const kid = "withdrawn"
	key := mustGenRSA(t)

	var empty atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if empty.Load() {
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		_, _ = w.Write([]byte(jwksDocFor(&key.PublicKey, kid)))
	}))
	defer srv.Close()

	clock := time.Unix(1_700_000_000, 0)
	cache := newCache(srv, clock)

	// Prime the cache with K.
	got, err := cache.key(context.Background(), kid, "RS256")
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	if _, ok := got.(*rsa.PublicKey); !ok {
		t.Fatalf("prime returned wrong type: %T", got)
	}

	// Switch the server to {"keys":[]} and advance past the TTL so the
	// next lookup actually performs a refresh.
	empty.Store(true)
	cache.now = func() time.Time { return clock.Add(jwksTTL + time.Second) }

	_, err = cache.key(context.Background(), kid, "RS256")
	if err == nil {
		t.Fatal("a lookup for the withdrawn kid must fail after an authoritative empty set")
	}
	// The error is the unknown-kid error wrapping ErrJWKS, not ErrJWKSStale
	// (the refresh succeeded; it just returned an empty set).
	if !errors.Is(err, ErrJWKS) {
		t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
	}
	if errors.Is(err, ErrJWKSStale) {
		t.Fatalf("err = %v, must not be ErrJWKSStale: the refresh itself succeeded", err)
	}
	if !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("err = %v, want a message containing \"unknown kid\"", err)
	}
}

// TestJWKS_concurrentColdStart pins down the rule that a cold-cache fetch must
// not refuse concurrent callers with "unknown kid" while another caller's
// refresh is still in flight: the in-flight refresh is joined via singleflight,
// and both lookups observe the populated cache.
//
// The second lookup only starts once the handler has the first request, so the
// second caller genuinely arrives during the fetch rather than after it.
func TestJWKS_concurrentColdStart(t *testing.T) {
	const kid = "shared"
	key := mustGenRSA(t)
	doc := jwksDocFor(&key.PublicKey, kid)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	cache := newCache(srv, time.Unix(1_700_000_000, 0))

	type result struct {
		key any
		err error
	}
	results := make(chan result, 2)
	lookup := func() {
		k, err := cache.key(context.Background(), kid, "RS256")
		results <- result{k, err}
	}

	go lookup()
	waitFor(t, entered, "the first fetch to reach the handler")

	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		lookup()
	}()
	<-secondStarted
	close(release)

	for i := 0; i < 2; i++ {
		r := waitFor(t, results, "a concurrent lookup to return")
		if r.err != nil {
			t.Fatalf("concurrent lookup failed: %v", r.err)
		}
		if _, ok := r.key.(*rsa.PublicKey); !ok {
			t.Fatalf("concurrent lookup returned %T, want *rsa.PublicKey", r.key)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("the cold-cache fetch should have hit the server exactly once, got %d", got)
	}
}

// TestJWKS_callerCancellationDoesNotBlockRetry: a first call whose context is
// cancelled mid-fetch must not record a failed attempt. The very next call
// with a live context must perform a fresh fetch and succeed.
func TestJWKS_callerCancellationDoesNotBlockRetry(t *testing.T) {
	const kid = "live"
	key := mustGenRSA(t)
	doc := jwksDocFor(&key.PublicKey, kid)

	var requests atomic.Int32
	handlerEntered := make(chan struct{}, 8)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerEntered <- struct{}{}
		n := requests.Add(1)
		if n == 1 {
			// Hold the first call open until its context is cancelled, so
			// the http client surfaces a context error to the cache rather
			// than a successful response.
			<-r.Context().Done()
			return
		}
		// Hold subsequent calls open until release, so the test observes
		// the retry reaching the handler before the response is delivered.
		<-release
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	cache := newCache(srv, time.Unix(1_700_000_000, 0))

	// First call: cancelled mid-fetch.
	ctxA, cancelA := context.WithCancel(context.Background())
	cancelObserved := make(chan struct{})
	go func() {
		waitFor(t, handlerEntered, "the handler to receive the first request")
		cancelA()
		close(cancelObserved)
	}()
	if _, err := cache.key(ctxA, kid, "RS256"); err == nil {
		t.Fatal("a cancelled call must not return a key")
	}
	<-cancelObserved

	// Retry with a live context. Wait for it to reach the handler, then
	// release the response.
	type result struct {
		key any
		err error
	}
	retryReturned := make(chan result, 1)
	go func() {
		k, err := cache.key(context.Background(), kid, "RS256")
		retryReturned <- result{k, err}
	}()
	waitFor(t, handlerEntered, "the retry to reach the handler")
	close(release)

	res := waitFor(t, retryReturned, "the retry to return")
	if res.err != nil {
		t.Fatalf("retry after cancellation failed: %v", res.err)
	}
	if _, ok := res.key.(*rsa.PublicKey); !ok {
		t.Fatalf("retry returned %T, want *rsa.PublicKey", res.key)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2 (the cancelled one plus the retry)", got)
	}
}
