package jwk_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestVerifyIDToken_ecOffCurveAndBadCurveRejected(t *testing.T) {
	signKey := oauthtest.MustRSA(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec: %v", err)
	}
	raw, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("ec bytes: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(raw[1:33])
	yGood := raw[33:65]
	yBad := append([]byte(nil), yGood...)
	yBad[len(yBad)-1] ^= 0xff // perturb y so the point is no longer on the curve

	// The end-to-end test only proves the verifier refuses to verify: an
	// off-curve point in the JWKS would be rejected because no key is found
	// for the kid, not because the on-curve check fired. The parser-level
	// test for the same input lives in jwks_bounds_internal_test.go and
	// pins the rejection text.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, oauthtest.KID, x, base64.RawURLEncoding.EncodeToString(yBad))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	tok := oauthtest.SignIDToken(t, signKey, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("off-curve point must be rejected by the verifier")
	}
}

func TestVerifyIDToken_rsaBoundsRejected(t *testing.T) {
	// The end-to-end test only proves the verifier refuses to verify: an
	// oversized modulus or a wide exponent would be rejected because no key
	// is found for the kid (or because signature verification fails), not
	// because the bounds check fired. The parser-level tests for the same
	// inputs live in jwks_bounds_internal_test.go and pin each bound by
	// name.
	key := oauthtest.MustRSA(t)
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":"AQAB"}]}`,
		oauthtest.KID, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 2049)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("out-of-range RSA key must be rejected by the verifier")
	}
}

func TestVerifyIDToken_encUseKeySkipped(t *testing.T) {
	key := oauthtest.MustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	// The only key carries use:"enc" — it must not be selected to verify a signature.
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"enc","n":%q,"e":%q}]}`, oauthtest.KID, n, e)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("an enc-use key must not verify a token signature")
	}
}

func TestVerifyIDToken_ecKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// SEC1 uncompressed point: 0x04 || x(32) || y(32). Avoids the deprecated
	// raw X/Y coordinate accessors.
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(raw[1:33])
	y := base64.RawURLEncoding.EncodeToString(raw[33:65])
	doc := fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, oauthtest.KID, x, y)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, oauthtest.ValidClaims(srv.URL, "n"))
	tok.Header["kid"] = oauthtest.KID
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}

	claims, err := c.VerifyIDToken(context.Background(), signed, "n")
	if err != nil {
		t.Fatalf("VerifyIDToken (EC): %v", err)
	}
	if claims.Subject != "user-abc" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}
