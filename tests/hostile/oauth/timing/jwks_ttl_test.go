package timing_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: someone who can make the client look at a token whenever they
// like, for as long as they like. Effects they want: keep a withdrawn signing
// key working past its expiry, or turn the client into a request amplifier
// aimed at the provider by presenting tokens the cache cannot satisfy. The
// cache trusts a key set for an hour and refreshes at most once a minute.

func TestHostile_JWKS_ttl_aWithdrawnKeyStopsWorkingWhenTheSetExpires(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, b := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		c := p.BubbleClient(t, nil)
		old := hostiletest.SignA(t, hostiletest.LongLived(nil))
		if _, err := hostiletest.Verify(t, c, old); err != nil {
			t.Fatalf("control: %v", err)
		}

		// The provider rotates to B and withdraws A. Inside the TTL the cached
		// set is still the truth the client has.
		p.JWKS.Store(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &b.PublicKey, nil)))
		time.Sleep(59 * time.Minute)
		if _, err := hostiletest.Verify(t, c, old); err != nil {
			t.Fatalf("59 minutes in, inside the TTL, the cached key was dropped: %v", err)
		}
		if n := p.JWKSHits.Load(); n != 1 {
			t.Fatalf("a known kid inside its TTL caused %d fetches, want 1", n)
		}

		time.Sleep(2 * time.Minute)
		got, err := hostiletest.Verify(t, c, old)
		hostiletest.MustRejectToken(t, got, err)
		if n := p.JWKSHits.Load(); n != 2 {
			t.Fatalf("expiry caused %d fetches in total, want exactly one refresh", n)
		}
		rotated := hostiletest.Mint{Key: b, Claims: hostiletest.LongLived(nil)}.String(t)
		if _, err := hostiletest.Verify(t, c, rotated); err != nil {
			t.Fatalf("the rotated key was not picked up at expiry: %v", err)
		}
	})
}

func TestHostile_JWKS_ttl_aProviderOutageNeverExtendsTrustPastExpiry(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, _ := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		c := p.BubbleClient(t, nil)
		tok := hostiletest.SignA(t, hostiletest.LongLived(nil))
		if _, err := hostiletest.Verify(t, c, tok); err != nil {
			t.Fatalf("control: %v", err)
		}
		p.JWKSFail.Store(true)

		// Inside the TTL a dead provider changes nothing: the cache serves.
		time.Sleep(30 * time.Minute)
		if _, err := hostiletest.Verify(t, c, tok); err != nil {
			t.Fatalf("an outage inside the TTL refused a cached key: %v", err)
		}

		// Past it the client must fail closed, and say why.
		time.Sleep(31 * time.Minute)
		for range 50 {
			got, err := hostiletest.Verify(t, c, tok)
			hostiletest.MustRejectToken(t, got, err)
			if !errors.Is(err, oauth.ErrJWKSStale) {
				t.Fatalf("the refusal does not say the keys are stale: %v", err)
			}
		}
		if n := p.JWKSHits.Load(); n != 2 {
			t.Fatalf("50 verifications during the outage caused %d fetches in total, want 2 (prime + one failed refresh)", n)
		}
	})
}

// An unknown kid presented in a loop may force a refresh, but never more than
// one per window, however long the loop runs and however many tokens it sends.
func TestHostile_JWKS_ttl_refreshLoopCostsAtMostOneFetchPerWindow(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, _ := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		c := p.BubbleClient(t, nil)

		const windows, perWindow = 5, 200
		for w := range windows {
			for i := range perWindow {
				tok := hostiletest.Mint{Key: a, Kid: fmt.Sprintf("ghost-%d-%d", w, i), Claims: hostiletest.LongLived(nil)}.String(t)
				got, err := hostiletest.Verify(t, c, tok)
				hostiletest.MustRejectToken(t, got, err)
				time.Sleep(200 * time.Millisecond) // 40 s of loop per window, so 200 tokens never leave it
			}
			time.Sleep(25 * time.Second) // close the one-minute window
		}
		if n := p.JWKSHits.Load(); n > windows {
			t.Fatalf("%d forged-kid tokens over %d windows caused %d fetches; the cap is one per window", windows*perWindow, windows, n)
		}
		if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.LongLived(nil))); err != nil {
			t.Fatalf("control: the loop broke verification for the real kid: %v", err)
		}
	})
}

// A failing provider is retried once a window, not once a request, and the
// failure of one window does not poison the next.
func TestHostile_JWKS_ttl_failingProviderIsRetriedOncePerWindowAndRecovers(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, _ := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		p.JWKSFail.Store(true)
		c := p.BubbleClient(t, nil)
		tok := hostiletest.SignA(t, hostiletest.LongLived(nil))

		for w := range 4 {
			for range 100 {
				got, err := hostiletest.Verify(t, c, tok)
				hostiletest.MustRejectToken(t, got, err)
			}
			if n := p.JWKSHits.Load(); n != int64(w+1) {
				t.Fatalf("after window %d the provider saw %d fetches, want %d", w, n, w+1)
			}
			time.Sleep(time.Minute)
		}
		p.JWKSFail.Store(false)
		if _, err := hostiletest.Verify(t, c, tok); err != nil {
			t.Fatalf("the client did not recover when the provider came back: %v", err)
		}
	})
}

// A hostile provider that answers an empty set must not let a key linger: the
// next verification after the refresh fails, with the old key gone at once.
func TestHostile_JWKS_ttl_emptySetEvictsTheKeyAtTheNextRefresh(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, _ := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		c := p.BubbleClient(t, nil)
		tok := hostiletest.SignA(t, hostiletest.LongLived(nil))
		if _, err := hostiletest.Verify(t, c, tok); err != nil {
			t.Fatalf("control: %v", err)
		}
		p.JWKS.Store(hostiletest.JWKSDoc())
		time.Sleep(61 * time.Minute)
		got, err := hostiletest.Verify(t, c, tok)
		hostiletest.MustRejectToken(t, got, err)
		time.Sleep(time.Second)
		if got, err := hostiletest.Verify(t, c, tok); err == nil {
			t.Fatalf("a key the provider withdrew verified again: %+v", got)
		}
	})
}
