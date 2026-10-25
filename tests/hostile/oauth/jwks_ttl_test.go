package hostile_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: someone who can make the client look at a token whenever they
// like, for as long as they like. Effects they want: keep a withdrawn signing
// key working past its expiry, or turn the client into a request amplifier
// aimed at the provider by presenting tokens the cache cannot satisfy. The
// cache trusts a key set for an hour and refreshes at most once a minute.

func TestHostile_JWKS_ttl_aWithdrawnKeyStopsWorkingWhenTheSetExpires(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, b := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)
		old := signA(t, longLived(nil))
		if _, err := verify(t, c, old); err != nil {
			t.Fatalf("control: %v", err)
		}

		// The provider rotates to B and withdraws A. Inside the TTL the cached
		// set is still the truth the client has.
		p.jwks.Store(jwksDoc(rsaJWK(testKID, &b.PublicKey, nil)))
		time.Sleep(59 * time.Minute)
		if _, err := verify(t, c, old); err != nil {
			t.Fatalf("59 minutes in, inside the TTL, the cached key was dropped: %v", err)
		}
		if n := p.jwksHits.Load(); n != 1 {
			t.Fatalf("a known kid inside its TTL caused %d fetches, want 1", n)
		}

		time.Sleep(2 * time.Minute)
		got, err := verify(t, c, old)
		mustRejectToken(t, got, err)
		if n := p.jwksHits.Load(); n != 2 {
			t.Fatalf("expiry caused %d fetches in total, want exactly one refresh", n)
		}
		rotated := mint{Key: b, Claims: longLived(nil)}.String(t)
		if _, err := verify(t, c, rotated); err != nil {
			t.Fatalf("the rotated key was not picked up at expiry: %v", err)
		}
	})
}

func TestHostile_JWKS_ttl_aProviderOutageNeverExtendsTrustPastExpiry(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)
		tok := signA(t, longLived(nil))
		if _, err := verify(t, c, tok); err != nil {
			t.Fatalf("control: %v", err)
		}
		p.jwksFail.Store(true)

		// Inside the TTL a dead provider changes nothing: the cache serves.
		time.Sleep(30 * time.Minute)
		if _, err := verify(t, c, tok); err != nil {
			t.Fatalf("an outage inside the TTL refused a cached key: %v", err)
		}

		// Past it the client must fail closed, and say why.
		time.Sleep(31 * time.Minute)
		for range 50 {
			got, err := verify(t, c, tok)
			mustRejectToken(t, got, err)
			if !errors.Is(err, oauth.ErrJWKSStale) {
				t.Fatalf("the refusal does not say the keys are stale: %v", err)
			}
		}
		if n := p.jwksHits.Load(); n != 2 {
			t.Fatalf("50 verifications during the outage caused %d fetches in total, want 2 (prime + one failed refresh)", n)
		}
	})
}

// An unknown kid presented in a loop may force a refresh, but never more than
// one per window, however long the loop runs and however many tokens it sends.
func TestHostile_JWKS_ttl_refreshLoopCostsAtMostOneFetchPerWindow(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)

		const windows, perWindow = 5, 200
		for w := range windows {
			for i := range perWindow {
				tok := mint{Key: a, Kid: fmt.Sprintf("ghost-%d-%d", w, i), Claims: longLived(nil)}.String(t)
				got, err := verify(t, c, tok)
				mustRejectToken(t, got, err)
				time.Sleep(200 * time.Millisecond) // 40 s of loop per window, so 200 tokens never leave it
			}
			time.Sleep(25 * time.Second) // close the one-minute window
		}
		if n := p.jwksHits.Load(); n > windows {
			t.Fatalf("%d forged-kid tokens over %d windows caused %d fetches; the cap is one per window", windows*perWindow, windows, n)
		}
		if _, err := verify(t, c, signA(t, longLived(nil))); err != nil {
			t.Fatalf("control: the loop broke verification for the real kid: %v", err)
		}
	})
}

// A failing provider is retried once a window, not once a request, and the
// failure of one window does not poison the next.
func TestHostile_JWKS_ttl_failingProviderIsRetriedOncePerWindowAndRecovers(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		p.jwksFail.Store(true)
		c := p.bubbleClient(t, nil)
		tok := signA(t, longLived(nil))

		for w := range 4 {
			for range 100 {
				got, err := verify(t, c, tok)
				mustRejectToken(t, got, err)
			}
			if n := p.jwksHits.Load(); n != int64(w+1) {
				t.Fatalf("after window %d the provider saw %d fetches, want %d", w, n, w+1)
			}
			time.Sleep(time.Minute)
		}
		p.jwksFail.Store(false)
		if _, err := verify(t, c, tok); err != nil {
			t.Fatalf("the client did not recover when the provider came back: %v", err)
		}
	})
}

// A hostile provider that answers an empty set must not let a key linger: the
// next verification after the refresh fails, with the old key gone at once.
func TestHostile_JWKS_ttl_emptySetEvictsTheKeyAtTheNextRefresh(t *testing.T) {
	inBubble(t, func(t *testing.T) {
		a, _ := rsaKeys()
		p := newProvider(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil)))
		c := p.bubbleClient(t, nil)
		tok := signA(t, longLived(nil))
		if _, err := verify(t, c, tok); err != nil {
			t.Fatalf("control: %v", err)
		}
		p.jwks.Store(jwksDoc())
		time.Sleep(61 * time.Minute)
		got, err := verify(t, c, tok)
		mustRejectToken(t, got, err)
		time.Sleep(time.Second)
		if got, err := verify(t, c, tok); err == nil {
			t.Fatalf("a key the provider withdrew verified again: %+v", got)
		}
	})
}
