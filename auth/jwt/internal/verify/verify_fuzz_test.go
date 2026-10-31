package verify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// FuzzVerifyAccessToken authenticates each mutation before comparing verdicts.
func FuzzVerifyAccessToken(f *testing.F) {
	seed := sha256.Sum256([]byte("access token signing fixture"))
	key := ed25519.NewKeyFromSeed(seed[:])
	pub := key.Public().(ed25519.PublicKey)
	now := time.Unix(1700000000, 0)
	p := verify.Params{Keys: map[string]ed25519.PublicKey{"test": pub}, Issuer: "issuer", Audience: "audience"}
	ref := hostiletest.RefPolicy{Kid: "test", Pub: pub, Issuer: "issuer", Audience: "audience", Typ: "access", Now: now}
	for _, offsets := range [][3]int64{{3600, -1, -1}, {0, -1, -1}, {-1, -1, -1}, {1, 0, 0}, {3600, 1, -1}, {3600, -1, 1}} {
		f.Add("issuer", "audience", hostiletest.Subject, "access", offsets[0], offsets[1], offsets[2], false)
	}
	f.Add("issuer", "audience", hostiletest.Subject, "access", int64(3600), int64(-1), int64(-1), true)
	f.Add("other", "audience", hostiletest.Subject, "access", int64(3600), int64(-1), int64(-1), false)
	f.Add("issuer", "audience", hostiletest.Subject, "refresh", int64(3600), int64(-1), int64(-1), false)
	f.Fuzz(func(t *testing.T, issuer, audience, subject, typ string, exp, iat, nbf int64, list bool) {
		// Bound dates to the common NumericDate domain and strings below the token cap.
		if len(issuer)+len(audience)+len(subject)+len(typ) > 256 {
			return
		}
		exp, iat, nbf = exp%86400, iat%86400, nbf%86400
		var aud any = audience
		if list {
			aud = []string{audience}
		}
		payload, err := json.Marshal(map[string]any{"iss": issuer, "aud": aud, "sub": subject, "jti": hostiletest.JtiA, "type": typ, "exp": now.Unix() + exp, "iat": now.Unix() + iat, "nbf": now.Unix() + nbf})
		if err != nil {
			t.Fatal(err)
		}
		b64 := base64.RawURLEncoding.EncodeToString
		input := b64([]byte(`{"alg":"EdDSA","kid":"test","typ":"JWT"}`)) + "." + b64(payload)
		token := input + "." + b64(ed25519.Sign(key, []byte(input)))
		claims, got := verify.Access[struct{}](context.Background(), p, now, token)
		want := hostiletest.RefVerify(token, ref)
		if (got == nil) != (want == nil) {
			t.Fatalf("verification = %v; reference = %v; payload=%s", got, want, payload)
		}
		if got == nil && claims.Subject != subject {
			t.Fatalf("subject = %q, want %q", claims.Subject, subject)
		}
	})
}
