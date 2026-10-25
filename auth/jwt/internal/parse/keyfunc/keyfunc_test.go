package keyfunc

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// The alg check has to be asserted directly. errmap.Map collapses everything
// into ErrTokenInvalid, so from outside there is no way to tell a token refused
// for its algorithm from one refused for a bad signature — which is why
// deleting the check leaves the end-to-end tests green.
func TestEdDSA_rejectsANonEdDSAAlg(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	fn := EdDSA(map[string]ed25519.PublicKey{kid: pub})

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

func TestEdDSA_returnsTheKeyForEdDSA(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "k1"
	fn := EdDSA(map[string]ed25519.PublicKey{kid: pub})

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

// A kid outside the set is refused, never replaced by "try every key": the
// verifier only trusts keys the operator authorised.
func TestEdDSA_refusesAnUnknownOrMissingKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fn := EdDSA(map[string]ed25519.PublicKey{"k1": pub})

	for name, kid := range map[string]any{"unknown": "k2", "missing": nil, "not a string": 7} {
		t.Run(name, func(t *testing.T) {
			tok := gjwt.New(gjwt.SigningMethodEdDSA)
			if kid != nil {
				tok.Header["kid"] = kid
			}

			key, err := fn(tok)
			if err == nil || key != nil {
				t.Fatalf("kid %v must be refused with no key, got %v, %v", kid, key, err)
			}
			if !strings.Contains(err.Error(), "unrecognised kid") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}
