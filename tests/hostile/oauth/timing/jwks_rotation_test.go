package timing_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Guards auth/oauth/internal/jwks/jwks.go:118 (unknown-kid cooldown),
// :132 (refresh), and :218 (replace the full set rather than merge old keys).
func TestHostile_JWKS_newKidAtCooldownReplacesTheUnexpiredSet(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		t.Run(fmt.Sprintf("overlap=%t", overlap), func(t *testing.T) {
			hostiletest.InBubble(t, func(t *testing.T) {
				a, b := hostiletest.RSAKeys()
				ka := hostiletest.RSAJWK("k1", &a.PublicKey, nil)
				kb := hostiletest.RSAJWK("k2", &b.PublicKey, nil)
				p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(ka))
				c := p.BubbleClient(t, nil)
				old := hostiletest.SignA(t, hostiletest.LongLived(nil))
				rotated := hostiletest.Mint{Key: b, Kid: "k2", Claims: hostiletest.LongLived(nil)}.String(t)
				if _, err := hostiletest.Verify(t, c, old); err != nil {
					t.Fatalf("prime: %v", err)
				}
				doc := hostiletest.JWKSDoc(kb)
				if overlap {
					doc = hostiletest.JWKSDoc(ka, kb)
				}
				p.JWKS.Store(doc)
				time.Sleep(time.Minute - time.Nanosecond)
				got, err := hostiletest.Verify(t, c, rotated)
				hostiletest.MustRejectToken(t, got, err)
				if n := p.JWKSHits.Load(); n != 1 {
					t.Fatalf("before cooldown: %d fetches, want 1", n)
				}
				time.Sleep(time.Nanosecond)
				if _, err := hostiletest.Verify(t, c, rotated); err != nil {
					t.Fatalf("new kid at cooldown: %v", err)
				}
				if n := p.JWKSHits.Load(); n != 2 {
					t.Fatalf("rotation: %d fetches, want 2", n)
				}
				got, err = hostiletest.Verify(t, c, old)
				if overlap {
					if err != nil || got == nil {
						t.Fatalf("intentional overlap lost: %v", err)
					}
				} else {
					hostiletest.MustRejectToken(t, got, err)
				}
				for i := range 32 {
					forged := hostiletest.Mint{Key: a, Kid: fmt.Sprintf("ghost-%d", i), Claims: hostiletest.LongLived(nil)}.String(t)
					got, err := hostiletest.Verify(t, c, forged)
					hostiletest.MustRejectToken(t, got, err)
				}
				if n := p.JWKSHits.Load(); n != 2 {
					t.Fatalf("post-refresh burst: %d fetches, want 2", n)
				}
				if _, err := hostiletest.Verify(t, c, rotated); err != nil {
					t.Fatalf("new key after burst: %v", err)
				}
			})
		})
	}
}
