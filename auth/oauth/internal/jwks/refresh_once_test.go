package jwks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A caller that looked at the cache before another caller's refresh finished
// must use that refresh, not open a flight of its own: the singleflight group
// only joins a flight that is still in the air, so without the check each such
// straggler cost the provider one more fetch inside the same window.
func TestJWKS_aStragglerUsesTheRefreshThatFinishedAfterItLooked(t *testing.T) {
	key := mustGenRSA(t)
	var fetches atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(jwksDocFor(&key.PublicKey, "k")))
	}))
	defer srv.Close()

	tick := time.Unix(1_700_000_000, 0)
	cache := New(srv.URL, srv.Client(), testErrs)
	cache.now = func() time.Time { tick = tick.Add(minRefreshInterval); return tick } // every read of the clock differs
	ctx := context.Background()

	var seen time.Time // what a caller saw before any refresh: no expiry at all
	if err := cache.refreshUnlessDone(ctx, seen); err != nil || fetches.Load() != 1 {
		t.Fatalf("a cold cache: err=%v fetches=%d, want one fetch", err, fetches.Load())
	}

	// The straggler looked while the cache was still empty; the refresh above
	// has finished since. It must not fetch again.
	if err := cache.refreshUnlessDone(ctx, seen); err != nil {
		t.Fatalf("straggler: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("a straggler caused %d fetches in total, want 1", got)
	}

	// A caller whose snapshot is the current one has nothing to borrow.
	cache.mu.RLock()
	current := cache.expiresAt
	cache.mu.RUnlock()
	if err := cache.refreshUnlessDone(ctx, current); err != nil || fetches.Load() != 2 {
		t.Fatalf("a caller holding the current expiry: err=%v fetches=%d, want a second fetch", err, fetches.Load())
	}

	// A failed refresh does not move the expiry, so it can never excuse a
	// straggler from fetching or from seeing the failure.
	down.Store(true)
	cache.mu.RLock()
	current = cache.expiresAt
	cache.mu.RUnlock()
	if err := cache.refreshUnlessDone(ctx, current); err == nil {
		t.Fatal("a failed refresh reported success")
	}
	if err := cache.refreshUnlessDone(ctx, current); err == nil || fetches.Load() != 4 {
		t.Fatalf("after a failure the expiry is unchanged, so the next caller fetches and fails too: err=%v fetches=%d", err, fetches.Load())
	}
}
