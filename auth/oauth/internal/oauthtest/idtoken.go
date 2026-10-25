package oauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// JWKSServer serves a JWKS document for pub under KID.
func JWKSServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, KID, n, e)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
}

// SignIDToken signs claims with key as RS256 under kid.
func SignIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims gjwt.MapClaims) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return s
}

// ValidClaims returns a claim set the verifier accepts for issuer and nonce.
func ValidClaims(issuer, nonce string) gjwt.MapClaims {
	return gjwt.MapClaims{
		"iss":            issuer,
		"aud":            ClientID,
		"sub":            "user-abc",
		"email":          "a@example.com",
		"email_verified": true,
		"nonce":          nonce,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
	}
}

// MustRSA generates a 2048-bit RSA key or fails the test.
func MustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}
