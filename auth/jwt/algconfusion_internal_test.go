package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// The attack: Ed25519 public keys are public by definition, so an attacker who
// knows one can mint an HS256 token using those very bytes as the HMAC secret.
// A verifier that hands the key to whichever method the token names verifies it
// happily, and every token can be forged.
//
// This asserts the outcome, and it passes even with the alg check in
// eddsaKeyFunc deleted — golang-jwt refuses the key on its own, because
// ed25519.PublicKey is a named type that does not assert to []byte and its HMAC
// verifier accepts nothing else. That second layer is real but incidental: it
// holds only while the keyfunc returns ed25519.PublicKey, and a refactor to
// return []byte(pub) would remove it silently. TestEddsaKeyFunc_rejectsANonEdDSAAlg
// below is what pins the check itself.
func TestVerifyAccessToken_refusesAnHS256TokenSignedWithThePublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	keys := map[string]ed25519.PublicKey{kid: pub}

	now := time.Now()
	claims := &accessClaims[map[string]any]{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "0192f0c1-0000-7000-8000-000000000000",
			Audience:  gjwt.ClaimStrings{"aud"},
			IssuedAt:  gjwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			ID:        "jti",
		},
		Type: tokenTypeAccess,
	}

	// Sign with HMAC, keyed on the public key's raw bytes.
	forged := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	forged.Header["kid"] = kid
	tokenStr, err := forged.SignedString([]byte(pub))
	if err != nil {
		t.Fatalf("sign the forged token: %v", err)
	}

	got, err := verifyAccessToken[map[string]any](tokenStr, keys, now, "issuer", "aud", 0)
	if err == nil {
		t.Fatalf("an HS256 token keyed on the public key was accepted — any token can be forged; claims: %+v", got)
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Logf("rejected, though not as ErrTokenInvalid: %v", err)
	}
}

// The alg check has to be asserted directly. mapJWTError collapses everything
// into ErrTokenInvalid, so from outside there is no way to tell a token refused
// for its algorithm from one refused for a bad signature — which is why
// deleting the check leaves the end-to-end tests green.
func TestEddsaKeyFunc_rejectsANonEdDSAAlg(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	fn := eddsaKeyFunc(map[string]ed25519.PublicKey{kid: pub})

	for name, method := range map[string]gjwt.SigningMethod{
		"HS256": gjwt.SigningMethodHS256,
		"RS256": gjwt.SigningMethodRS256,
		"none":  gjwt.SigningMethodNone,
	} {
		t.Run(name, func(t *testing.T) {
			tok := gjwt.New(method)
			tok.Header["kid"] = kid

			key, err := fn(tok)
			if err == nil {
				t.Fatalf("alg %s must be refused before any key is handed out, got key %T", name, key)
			}
			if !strings.Contains(err.Error(), "unexpected alg") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if key != nil {
				t.Fatalf("no key may be returned alongside the rejection, got %T", key)
			}
		})
	}
}

func TestEddsaKeyFunc_returnsTheKeyForEdDSA(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	fn := eddsaKeyFunc(map[string]ed25519.PublicKey{kid: pub})

	tok := gjwt.New(gjwt.SigningMethodEdDSA)
	tok.Header["kid"] = kid

	key, err := fn(tok)
	if err != nil {
		t.Fatalf("EdDSA must be accepted: %v", err)
	}
	// The concrete type matters: it is what stops golang-jwt handing these
	// bytes to an HMAC verifier. Returning []byte here would be a silent
	// downgrade.
	got, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("keyfunc must return ed25519.PublicKey, got %T", key)
	}
	if !got.Equal(pub) {
		t.Fatal("keyfunc returned a different key")
	}
}
