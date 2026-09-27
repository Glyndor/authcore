package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// appleP8PEMFor generates a fresh P-256 key, marshals it as PKCS#8, and
// PEM-encodes it as a single "PRIVATE KEY" block with no headers and only
// whitespace around it. The returned bytes are exactly what Apple delivers
// from the Developer portal.
func appleP8PEMFor(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestAppleClientSecret_Acceptance signs one secret, parses it back with
// the public key, and pins every header and claim the contract requires.
// It then calls the func a second time and asserts the two signatures
// differ, so a regression that returned a cached token would produce
// equal bytes.
//
// The clock is injected so the parser sees an exp in its future relative
// to the iat the signer stamped: jwt v5 uses its own clock for exp
// validation by default, and a real-time parser would see the signed exp
// fall behind when the signer pinned "now" to a fixed instant. Both the
// signer and the parser agree on the same TimeFunc here so the comparison
// is exact, and the iat is pinned against that value.
func TestAppleClientSecret_Acceptance(t *testing.T) {
	t.Parallel()
	p8 := appleP8PEMFor(t)
	team := appleTestTeamID
	kid := appleTestKeyID
	svc := appleTestClientID

	// Pin the clock well ahead of any real-world timestamp the parser
	// might check against, and use the same clock in the verifier.
	fixed := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := nowFn
	t.Cleanup(func() { nowFn = prev })
	nowFn = func() time.Time { return fixed }

	sign, err := AppleClientSecret(team, kid, svc, p8)
	if err != nil {
		t.Fatalf("AppleClientSecret: %v", err)
	}
	tok1, err := sign(context.Background())
	if err != nil {
		t.Fatalf("sign #1: %v", err)
	}
	tok2, err := sign(context.Background())
	if err != nil {
		t.Fatalf("sign #2: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("two calls must produce different signatures (they share iat/exp but different JWS signatures)")
	}

	pub, ok := applePublicFromPEM(t, p8).(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the test key was not ECDSA")
	}
	parsed, err := gjwt.Parse(tok1, func(t *gjwt.Token) (any, error) {
		return pub, nil
	},
		gjwt.WithValidMethods([]string{"ES256"}),
		gjwt.WithTimeFunc(func() time.Time { return fixed }),
	)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed token must validate")
	}
	if hdr, _ := parsed.Header["kid"].(string); hdr != kid {
		t.Errorf("header kid = %q, want %q", hdr, kid)
	}
	claims, ok := parsed.Claims.(gjwt.MapClaims)
	if !ok {
		t.Fatalf("claims = %T, want MapClaims", parsed.Claims)
	}
	if iss, _ := claims["iss"].(string); iss != team {
		t.Errorf("claims iss = %q, want %q", iss, team)
	}
	if sub, _ := claims["sub"].(string); sub != svc {
		t.Errorf("claims sub = %q, want %q", sub, svc)
	}
	switch a := claims["aud"].(type) {
	case string:
		if a != "https://appleid.apple.com" {
			t.Errorf("claims aud = %q, want https://appleid.apple.com", a)
		}
	default:
		t.Errorf("claims aud = %T, want a single string equal to https://appleid.apple.com", a)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int(exp-iat) != int(appleSecretLifetime.Seconds()) {
		t.Errorf("exp - iat = %v, want %v", exp-iat, appleSecretLifetime.Seconds())
	}
	if int64(iat) != fixed.Unix() {
		t.Errorf("iat = %v, want %v", iat, fixed.Unix())
	}
}

// TestAppleClientSecret_Refusals is the table of refusals. Each row
// produces an ErrInvalidConfig that names the offending field in its
// message; a regression that lifts a guard or moves it onto a different
// field shows up here rather than at the Apple token endpoint. The
// extra check that no 16-byte substring of the parsed key's base64 body
// appears in any error message covers every refusal uniformly: a leak
// anywhere in the parser path is caught here.
func TestAppleClientSecret_Refusals(t *testing.T) {
	t.Parallel()
	validP8 := appleP8PEMFor(t)
	mkOtherPEM := func(t *testing.T, blkType string, der []byte) []byte {
		t.Helper()
		return pem.EncodeToMemory(&pem.Block{Type: blkType, Bytes: der})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384: %v", err)
	}
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatalf("marshal p384: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(p256)
	if err != nil {
		t.Fatalf("marshal sec1: %v", err)
	}
	twoBlocks := append([]byte{}, validP8...)
	twoBlocks = append(twoBlocks, '\n')
	twoBlocks = append(twoBlocks, validP8...)
	p8WithProc := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Bytes:   pemBytes(t, validP8),
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
	})
	p8LeadingText := append([]byte("Bag Attributes\n    friendlyName: k\n"), validP8...)

	cases := map[string]struct {
		team, key, svc string
		p8             []byte
		fragment       string
	}{
		"team id 9 chars":           {"ABCDE1234", appleTestKeyID, appleTestClientID, validP8, "team ID"},
		"team id 11 chars":          {"ABCDE123456", appleTestKeyID, appleTestClientID, validP8, "team ID"},
		"team id lowercase":         {"ABCDE1234a", appleTestKeyID, appleTestClientID, validP8, "team ID"},
		"key id 9 chars":            {appleTestTeamID, "KEYID6789", appleTestClientID, validP8, "key ID"},
		"key id 11 chars":           {appleTestTeamID, "KEYID678901", appleTestClientID, validP8, "key ID"},
		"key id lowercase":          {appleTestTeamID, "keyid67890", appleTestClientID, validP8, "key ID"},
		"empty client id":           {appleTestTeamID, appleTestKeyID, "   \t\n ", validP8, "client ID must not be empty"},
		"client id with spaces":     {appleTestTeamID, appleTestKeyID, " com.example.web", validP8, "client ID must not be empty or carry surrounding whitespace"},
		"RSA 2048 PKCS#8":           {appleTestTeamID, appleTestKeyID, appleTestClientID, mkOtherPEM(t, "PRIVATE KEY", rsaDER), "ECDSA"},
		"Ed25519 PKCS#8":            {appleTestTeamID, appleTestKeyID, appleTestClientID, mkOtherPEM(t, "PRIVATE KEY", edDER), "ECDSA"},
		"P-384 PKCS#8":              {appleTestTeamID, appleTestKeyID, appleTestClientID, mkOtherPEM(t, "PRIVATE KEY", p384DER), "P-256"},
		"EC PRIVATE KEY":            {appleTestTeamID, appleTestKeyID, appleTestClientID, mkOtherPEM(t, "EC PRIVATE KEY", sec1DER), `labelled "EC PRIVATE KEY", want "PRIVATE KEY"`},
		"two PEM blocks":            {appleTestTeamID, appleTestKeyID, appleTestClientID, twoBlocks, "more than one PEM block"},
		"trailing text":             {appleTestTeamID, appleTestKeyID, appleTestClientID, append(append([]byte{}, validP8...), '\n', 'X'), "more than one PEM block"},
		"text before the PEM block": {appleTestTeamID, appleTestKeyID, appleTestClientID, p8LeadingText, "does not start with a PEM block"},
		"headers in block":          {appleTestTeamID, appleTestKeyID, appleTestClientID, p8WithProc, "headers"},
		"non-PEM bytes":             {appleTestTeamID, appleTestKeyID, appleTestClientID, []byte("not a PEM block at all"), "does not start with a PEM block"},
	}

	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := AppleClientSecret(c.team, c.key, c.svc, c.p8)
			if err == nil {
				t.Fatalf("AppleClientSecret: expected refusal, got nil")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("refusal must wrap ErrInvalidConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), c.fragment) {
				t.Fatalf("refusal must contain %q, got %v", c.fragment, err)
			}
			body := appleBase64Body(c.p8)
			if body != "" {
				for i := 0; i+16 <= len(body); i++ {
					sub := body[i : i+16]
					if strings.Contains(err.Error(), sub) {
						t.Fatalf("refusal leaks a 16-byte substring of the key body: %q (in %q)", sub, err)
					}
				}
			}
		})
	}
}

// TestAppleClientSecret_CancelledContext pins that a cancelled context
// short-circuits signing without producing a token. The error surfaces
// unwrapped on purpose: context errors are not a key leak.
func TestAppleClientSecret_CancelledContext(t *testing.T) {
	t.Parallel()
	sign, err := AppleClientSecret(appleTestTeamID, appleTestKeyID, appleTestClientID, appleP8PEMFor(t))
	if err != nil {
		t.Fatalf("AppleClientSecret: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tok, err := sign(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if tok != "" {
		t.Errorf("a cancelled context must not produce a token, got %q", tok)
	}
}

// applePublicFromPEM decodes an Apple-format p8 and returns its public key.
func applePublicFromPEM(t *testing.T, p8 []byte) any {
	t.Helper()
	block, _ := pem.Decode(p8)
	if block == nil {
		t.Fatal("decode p8")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse p8: %v", err)
	}
	if ec, ok := key.(*ecdsa.PrivateKey); ok {
		return &ec.PublicKey
	}
	return nil
}

// pemBytes returns the body of the FIRST PEM block in p8. Used to build
// a synthetic block carrying an RFC 1423 header. pem.EncodeToMemory does
// not accept a Headers field when the body is empty.
func pemBytes(t *testing.T, p8 []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(p8)
	if block == nil {
		t.Fatal("decode p8")
	}
	return block.Bytes
}
