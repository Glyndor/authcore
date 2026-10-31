package timing_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Guards auth/oauth/internal/jwks/jwks.go:218 (whole Candidate replacement),
// auth/oauth/internal/jwks/fetch/fetch.go:123 (metadata retention), and
// auth/oauth/internal/idtoken/idtoken.go:156 (key issuer enforcement).
func TestHostile_JWKS_refreshTightensMetadataOnTheSamePublicKey(t *testing.T) {
	const other = "https://idp.example/tenant-two"
	for _, tc := range []struct {
		name     string
		metadata map[string]any
		reason   string
	}{
		{"use", map[string]any{"use": "enc"}, ""},
		{"key_ops", map[string]any{"key_ops": []string{"encrypt"}}, ""},
		{"alg", map[string]any{"alg": "PS256"}, ""},
		{"issuer", map[string]any{"issuer": other}, "restricted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostiletest.InBubble(t, func(t *testing.T) {
				a, _ := hostiletest.RSAKeys()
				doc := func(meta map[string]any) []byte {
					return hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, meta))
				}
				p := hostiletest.NewMemProvider(doc(nil))
				c := p.BubbleClient(t, func(cfg *oauth.Config) {
					// Both issuers pass the client policy; rejection of the old token
					// after refresh can therefore only come from the JWK restriction.
					cfg.IssuerValidator = func(iss string) bool { return iss == hostiletest.Issuer || iss == other }
				})
				token := hostiletest.SignA(t, hostiletest.LongLived(nil))
				if _, err := hostiletest.Verify(t, c, token); err != nil {
					t.Fatalf("prime: %v", err)
				}
				p.JWKS.Store(doc(tc.metadata))
				time.Sleep(time.Hour - time.Nanosecond)
				if _, err := hostiletest.Verify(t, c, token); err != nil {
					t.Fatalf("before expiry: %v", err)
				}
				if n := p.JWKSHits.Load(); n != 1 {
					t.Fatalf("before expiry: %d fetches, want 1", n)
				}
				time.Sleep(time.Nanosecond)
				got, err := hostiletest.Verify(t, c, token)
				hostiletest.MustRejectToken(t, got, err)
				if got != nil {
					t.Fatalf("restricted key returned claims: %+v", got)
				}
				if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("wrong refusal: %v", err)
				}
				if n := p.JWKSHits.Load(); n != 2 {
					t.Fatalf("expiry: %d fetches, want 2", n)
				}
				if tc.name == "issuer" {
					allowed := hostiletest.SignA(t, hostiletest.LongLived(map[string]any{"iss": other}))
					if _, err := hostiletest.Verify(t, c, allowed); err != nil {
						t.Fatalf("newly permitted issuer: %v", err)
					}
				}
				// Restore only metadata, keeping kid and public bytes unchanged again.
				// This control also detects a client that simply refuses all refreshes.
				p.JWKS.Store(doc(nil))
				time.Sleep(time.Hour)
				if _, err := hostiletest.Verify(t, c, token); err != nil {
					t.Fatalf("restored metadata: %v", err)
				}
				if n := p.JWKSHits.Load(); n != 3 {
					t.Fatalf("restoration: %d fetches, want 3", n)
				}
			})
		})
	}
}
