package oauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Two behaviours of the JWKS cache during a provider outage, pinned on
// 2026-09-25: a stale kid does not fetch again inside the cooldown after a
// failed refresh, and a caller that joined a fetch whose starter went away
// fetches again instead of inheriting that cancellation.

func TestJWKS_staleKidWaitsOutTheCooldownAfterAFailedRefresh(t *testing.T) {
	const kid = "k"
	key := mustGenRSA(t)
	var fetches atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(jwksDocFor(&key.PublicKey, kid)))
	}))
	defer srv.Close()

	clock := time.Unix(1_700_000_000, 0)
	cache := newCache(srv, clock)
	if _, err := cache.key(context.Background(), kid, "RS256"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	down.Store(true)
	expired := clock.Add(jwksTTL + time.Second)
	cache.now = func() time.Time { return expired }
	if _, err := cache.key(context.Background(), kid, "RS256"); !errors.Is(err, ErrJWKSStale) {
		t.Fatalf("first lookup after expiry: %v, want ErrJWKSStale", err)
	}
	afterFirst := fetches.Load()

	for i := 0; i < 5; i++ {
		_, err := cache.key(context.Background(), kid, "RS256")
		if !errors.Is(err, ErrJWKSStale) || !errors.Is(err, ErrJWKS) || !strings.Contains(err.Error(), "the last refresh failed less than") {
			t.Fatalf("lookup %d inside the cooldown: %v, want the cooldown refusal", i, err)
		}
	}
	if got := fetches.Load(); got != afterFirst {
		t.Fatalf("%d fetches inside the cooldown, want none", got-afterFirst)
	}

	// Past the cooldown, with the provider back, the next lookup fetches and
	// serves the key again.
	down.Store(false)
	cache.now = func() time.Time { return expired.Add(minRefreshInterval) }
	if _, err := cache.key(context.Background(), kid, "RS256"); err != nil {
		t.Fatalf("lookup after the cooldown with the provider back: %v", err)
	}
	if got := fetches.Load(); got != afterFirst+1 {
		t.Fatalf("%d fetches after the cooldown, want exactly one", got-afterFirst)
	}
}

// gatedTransport holds the first request until its context is done and
// serves doc to every later one. Everything it blocks on belongs to the
// synctest bubble, so synctest.Wait can tell when both callers are parked.
type gatedTransport struct {
	calls   atomic.Int32
	entered chan struct{}
	doc     string
}

func (g *gatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.calls.Add(1) == 1 {
		close(g.entered)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(g.doc)),
		Request:    req,
	}, nil
}

func TestJWKS_joinedCallerRetriesWhenTheStarterIsCancelled(t *testing.T) {
	key := mustGenRSA(t)
	synctest.Test(t, func(t *testing.T) {
		const kid = "k"
		rt := &gatedTransport{entered: make(chan struct{}), doc: jwksDocFor(&key.PublicKey, kid)}
		cache := newJWKSCache("https://keys.example/jwks", &http.Client{Transport: rt})

		ctxA, cancelA := context.WithCancel(context.Background())
		errA := make(chan error, 1)
		go func() {
			_, err := cache.key(ctxA, kid, "RS256")
			errA <- err
		}()
		<-rt.entered

		type result struct {
			key any
			err error
		}
		resB := make(chan result, 1)
		go func() {
			k, err := cache.key(context.Background(), kid, "RS256")
			resB <- result{k, err}
		}()
		// B is now parked on A's in-flight fetch, and A on its request.
		synctest.Wait()
		cancelA()

		if err := <-errA; !errors.Is(err, context.Canceled) {
			t.Fatalf("the cancelled starter got %v, want context.Canceled", err)
		}
		got := <-resB
		if got.err != nil {
			t.Fatalf("the joined caller with a live context got %v, want the key", got.err)
		}
		if _, ok := got.key.(*rsa.PublicKey); !ok {
			t.Fatalf("the joined caller got %T, want *rsa.PublicKey", got.key)
		}
		if n := rt.calls.Load(); n != 2 {
			t.Fatalf("%d requests, want 2: the cancelled one and the retry", n)
		}
	})
}
