package keyfunc

import (
	"crypto/ed25519"
	"errors"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

func TestEdDSA_refusesCriticalHeaders(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fn := EdDSA(map[string]ed25519.PublicKey{"k1": pub})
	for name, crit := range map[string]any{
		"extension": []any{"policy"},
		"empty":     []any{},
		"null":      nil,
		"string":    "policy",
	} {
		t.Run(name, func(t *testing.T) {
			tok := gjwt.New(gjwt.SigningMethodEdDSA)
			tok.Header["kid"] = "k1"
			tok.Header["crit"] = crit
			key, err := fn(tok)
			if key != nil || !errors.Is(err, jwterr.ErrTokenInvalid) {
				t.Fatalf("keyfunc with crit = %v, %v; want nil and ErrTokenInvalid", key, err)
			}
		})
	}
}
