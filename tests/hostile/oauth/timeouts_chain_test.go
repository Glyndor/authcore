package hostile_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: a provider (or a path to it) that accepts the connection and then
// says nothing. One stalled call is bounded by the client's timeout; the
// question here is what many of them cost together: a login is an Exchange
// followed by a key fetch, and a flood of logins is many of those at once.
// Time is virtual (see vclock_test.go), so a ten-second stall costs nothing.

// elapsed runs f and returns how much virtual time it took.
func elapsed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func TestHostile_Timeouts_stackedStallsAreEachBoundedAndCannotExceedTheCallersDeadline(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		p.stall.Store(true)
		c := p.bubbleClient(t, nil) // the default ten-second timeout applies

		var exErr, vErr error
		cx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
		defer cancel()
		took := elapsed(func() {
			_, exErr = c.Exchange(cx, "code", "verifier")
			_, vErr = c.VerifyIDToken(cx, signA(t, longLived(nil)), testNonce)
		})
		if !errors.Is(exErr, oauth.ErrExchange) {
			t.Errorf("a stalled token endpoint: %v, want ErrExchange", exErr)
		}
		if vErr == nil {
			t.Error("a token verified against a stalled key endpoint")
		}
		if took > 14*time.Second+time.Second {
			t.Fatalf("a login against a stalled provider took %s, past the caller's 14 s deadline", took)
		}
		if took < 14*time.Second-time.Second {
			t.Fatalf("both stalls ended after %s, before the 10 s + 4 s they should have taken; a timeout is not being honoured", took)
		}
	})
}

func TestHostile_Timeouts_stallsRunInParallelAndNeverQueueBehindEachOther(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		p := newProvider(nil)
		p.stall.Store(true)
		c := p.bubbleClient(t, nil)
		a, _ := rsaKeys()
		p.jwks.Store(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))

		const n = 80
		var wg sync.WaitGroup
		took := elapsed(func() {
			for range n {
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = c.Exchange(context.Background(), "code", "verifier")
				}()
				go func() {
					defer wg.Done()
					_, _ = c.VerifyIDToken(context.Background(), signA(t, longLived(nil)), testNonce)
				}()
			}
			wg.Wait()
		})
		if took > 11*time.Second {
			t.Fatalf("%d concurrent stalled logins took %s; they queued instead of timing out together at 10 s", n, took)
		}
		if got := p.jwksHits.Load(); got != 1 {
			t.Fatalf("%d concurrent verifications against a stalled key endpoint caused %d fetches, want 1", n, got)
		}
	})
}

// After a stalled key fetch times out, callers inside the window are refused
// at once instead of each waiting out their own ten seconds.
func TestHostile_Timeouts_aStalledKeyEndpointIsNotWaitedOnTwiceInAWindow(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		p.stall.Store(true)
		c := p.bubbleClient(t, nil)

		var first error
		if d := elapsed(func() { _, first = c.VerifyIDToken(context.Background(), signA(t, longLived(nil)), testNonce) }); d < 9*time.Second || d > 11*time.Second {
			t.Fatalf("the first verification waited %s, want about the 10 s client timeout", d)
		}
		if !errors.Is(first, oauth.ErrIDTokenInvalid) {
			t.Fatalf("first: %v", first)
		}
		took := elapsed(func() {
			for range 100 {
				if _, err := c.VerifyIDToken(context.Background(), signA(t, longLived(nil)), testNonce); err == nil {
					t.Error("accepted while the key endpoint stalls")
				}
			}
		})
		if took > time.Second {
			t.Fatalf("100 follow-up verifications waited %s on a provider already known to stall", took)
		}
		if n := p.jwksHits.Load(); n != 1 {
			t.Fatalf("the stalled provider received %d fetches inside one window, want 1", n)
		}
	})
}

// A provider that answers just inside the timeout, over and over, gains
// nothing: each Exchange is its own bounded call, and none waits on another.
func TestHostile_Timeouts_aSlowButAnsweringProviderCannotAccumulateDelay(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		const slow = 9 * time.Second
		body := []byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`)
		rt := rtFunc(func(r *http.Request) (*http.Response, error) {
			select {
			case <-time.After(slow):
				return memResponse(r, http.StatusOK, body), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		})
		c := oidcClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
			c.HTTPClient = &http.Client{Transport: rt}
			c.Provider.TokenURL = "https://idp.example/token"
		})
		for i := range 5 {
			var err error
			d := elapsed(func() { _, err = c.Exchange(context.Background(), "code", "verifier") })
			if err != nil {
				t.Fatalf("exchange %d: %v", i, err)
			}
			if d != slow {
				t.Fatalf("exchange %d took %s, want the provider's own %s and nothing added", i, d, slow)
			}
		}
	})
}
