package jwttest

import (
	"crypto/ed25519"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
)

// SignAccess signs claims.Access with the EdDSA method and a kid header for
// verification with a rig that holds the matching public key. Used to
// construct hand-crafted tokens whose only difference from a real one is the
// claim under test.
func SignAccess[T any](t testing.TB, cl *claims.Access[T], priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	return sign(t, cl, priv, kid)
}

// SignRefresh is the refresh-claims mirror of SignAccess.
func SignRefresh(t testing.TB, cl *claims.Refresh, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	return sign(t, cl, priv, kid)
}

func sign(t testing.TB, cl gjwt.Claims, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, cl)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return signed
}
