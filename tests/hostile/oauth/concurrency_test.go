package hostile_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: a crowd. Many logins finish at once, some of them forged, while
// the key cache expires and refreshes under them and the token endpoint is
// being called. The race detector is half of the assertion; the other half is
// that no interleaving turns a refusal into an acceptance or the reverse, and
// that the provider still sees one fetch per refresh rather than one per caller.

// Phase one: keys A are published. Phase two: the provider rotated to keys B at
// the start and the cached set expires while every worker is mid-flight.
func TestHostile_Concurrency_aKeyRotationUnderLoadNeverFlipsAnAnswer(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, b := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)
		tokA := mint{Key: a, Claims: longLived(nil)}.String(t)
		tokB := mint{Key: b, Claims: longLived(nil)}.String(t)

		// run starts workers that verify tokens signed by A and by B and counts
		// every answer that disagrees with what the era allows.
		run := func(aOK, bOK bool) int64 {
			var wrong atomic.Int64
			var wg sync.WaitGroup
			for range 24 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 30 {
						if _, err := c.VerifyIDToken(t.Context(), tokA, testNonce); (err == nil) != aOK {
							wrong.Add(1)
						}
						if _, err := c.VerifyIDToken(t.Context(), tokB, testNonce); (err == nil) != bOK {
							wrong.Add(1)
						}
						time.Sleep(time.Second)
					}
				}()
			}
			wg.Wait()
			return wrong.Load()
		}

		// Era one lasts 30 virtual seconds. The provider switches keys inside it,
		// but the cache is not due to look until the hour is up.
		go func() { time.Sleep(10 * time.Second); p.jwks.Store(jwksDoc(rsaJWK(testKID, &b.PublicKey, nil))) }()
		if n := run(true, false); n != 0 {
			t.Fatalf("era one: %d answers disagreed with the cached keys", n)
		}
		time.Sleep(time.Hour) // the set expires with no worker running...
		if n := run(false, true); n != 0 {
			t.Fatalf("era two: %d answers disagreed with the rotated keys", n)
		}
		if got := p.jwksHits.Load(); got != 2 {
			t.Fatalf("1440 verifications over two eras caused %d key fetches, want 2", got)
		}
	})
}

// ...and the same, with the expiry landing in the middle of a busy period.
func TestHostile_Concurrency_theExpiryLandingMidBurstCollapsesIntoOneFetch(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)
		tok := mint{Key: a, Claims: longLived(nil)}.String(t)
		if _, err := c.VerifyIDToken(t.Context(), tok, testNonce); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour + time.Second) // due

		var wg sync.WaitGroup
		var bad atomic.Int64
		for range 64 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.VerifyIDToken(t.Context(), tok, testNonce); err != nil {
					bad.Add(1)
				}
			}()
		}
		wg.Wait()
		if bad.Load() != 0 {
			t.Fatalf("%d verifications failed across a healthy refresh", bad.Load())
		}
		if got := p.jwksHits.Load(); got != 2 {
			t.Fatalf("64 simultaneous callers at expiry caused %d fetches in total, want 2", got)
		}
	})
}

// Exchange, verify and the authorization request on one shared client, from
// many goroutines, against a real HTTP server.
func TestHostile_Concurrency_theWholeFlowOnOneSharedClient(t *testing.T) {
	a, _ := rsaKeys()
	idt := mint{Key: a, Claims: claims(testNonce, nil)}.String(t)
	body := tokenBody(map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": idt})
	jwks := serve(t, staticBody(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil))))
	tokens := serve(t, staticBody(body))
	c := oidcClient(t, jwks.URL, func(cfg *oauth.Config) {
		cfg.Provider.TokenURL, cfg.ClientSecret = tokens.URL, "s"
	})

	const workers, rounds = 24, 15
	var wg sync.WaitGroup
	var failures atomic.Int64
	var firstErr atomic.Value
	fail := func(err error) {
		failures.Add(1)
		firstErr.CompareAndSwap(nil, err.Error())
	}
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				if _, err := c.AuthCodeURL(); err != nil {
					fail(err)
				}
				tok, err := c.Exchange(ctx(t), fmt.Sprintf("code-%d-%d", w, r), "verifier")
				if err != nil {
					fail(err)
					continue
				}
				if _, err := c.VerifyIDToken(ctx(t), tok.IDToken, testNonce); err != nil {
					fail(err)
				}
				if _, err := c.VerifyIDToken(ctx(t), tok.IDToken, "not-the-nonce"); err == nil {
					fail(fmt.Errorf("a wrong nonce was accepted"))
				}
			}
		}()
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of %d concurrent flows failed, first: %v", n, workers*rounds, firstErr.Load())
	}
	if n := jwks.hits.Load(); n != 1 {
		t.Fatalf("%d flows fetched the keys %d times, want 1", workers*rounds, n)
	}
	if n := tokens.hits.Load(); n != workers*rounds {
		t.Fatalf("the token endpoint saw %d requests for %d exchanges", n, workers*rounds)
	}
}
