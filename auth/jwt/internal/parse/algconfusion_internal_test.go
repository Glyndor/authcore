package parse

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
)

// The attack: Ed25519 public keys are public by definition, so an attacker who
// knows one can mint an HS256 token using those very bytes as the HMAC secret.
// A verifier that hands the key to whichever method the token names verifies it
// happily, and every token can be forged.
//
// This asserts the outcome, and it passes even with the alg check in
// keyfunc.EdDSA deleted — golang-jwt refuses the key on its own, because
// ed25519.PublicKey is a named type that does not assert to []byte and its HMAC
// verifier accepts nothing else. That second layer is real but incidental: it
// holds only while the keyfunc returns ed25519.PublicKey, and a refactor to
// return []byte(pub) would remove it silently. TestEdDSA_rejectsANonEdDSAAlg
// in the keyfunc package is what pins the check itself.
func TestVerifyAccessToken_refusesAnHS256TokenSignedWithThePublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	keys := map[string]ed25519.PublicKey{kid: pub}

	now := time.Now()
	cl := &claims.Access[map[string]any]{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "0192f0c1-0000-7000-8000-000000000000",
			Audience:  gjwt.ClaimStrings{"aud"},
			IssuedAt:  gjwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			ID:        "jti",
		},
		Type: claims.TypeAccess,
	}

	// Sign with HMAC, keyed on the public key's raw bytes.
	forged := gjwt.NewWithClaims(gjwt.SigningMethodHS256, cl)
	forged.Header["kid"] = kid
	tokenStr, err := forged.SignedString([]byte(pub))
	if err != nil {
		t.Fatalf("sign the forged token: %v", err)
	}

	got, err := Access[map[string]any](tokenStr, keys, now, "issuer", "aud", 0)
	if err == nil {
		t.Fatalf("an HS256 token keyed on the public key was accepted — any token can be forged; claims: %+v", got)
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Logf("rejected, though not as ErrTokenInvalid: %v", err)
	}
}
