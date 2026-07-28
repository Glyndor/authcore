package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// The bounds in parseJWK reject key material a hostile or broken JWKS document
// can otherwise hand the verifier: an undersized RSA modulus that is cheap to
// factor, an oversized one that turns every verification into a CPU sink, and
// EC coordinates outside the field. Every one of them survived being deleted
// with the suite green, because the end-to-end tests build only well-formed
// keys — so they are driven here directly.

func b64(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }

func rsaJWK(t *testing.T, bits int) jwk {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate %d-bit RSA key: %v", bits, err)
	}
	return jwk{Kty: "RSA", N: b64(k.N), E: b64(big.NewInt(int64(k.E)))}
}

func TestParseJWK_rejectsAnUndersizedRSAModulus(t *testing.T) {
	// 1024 bits is generatable and plausible-looking, and well under the floor.
	_, err := parseJWK(rsaJWK(t, 1024))
	if err == nil {
		t.Fatal("a 1024-bit RSA key must be refused")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestParseJWK_acceptsAnRSAKeyAtTheFloor(t *testing.T) {
	if _, err := parseJWK(rsaJWK(t, 2048)); err != nil {
		t.Fatalf("2048 bits is the floor and must be accepted, got: %v", err)
	}
}

func TestParseJWK_rejectsAnOversizedRSAModulus(t *testing.T) {
	// Generating a >16384-bit key takes minutes, so the modulus is synthesised
	// directly: parseJWK only measures its bit length.
	huge := new(big.Int).Lsh(big.NewInt(1), 16385)
	_, err := parseJWK(jwk{Kty: "RSA", N: b64(huge), E: b64(big.NewInt(65537))})
	if err == nil {
		t.Fatal("a 16385-bit modulus must be refused — every verification would be a modexp on it")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestParseJWK_rejectsECCoordinatesOutsideTheField(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	// One coordinate longer than the curve's field size: on curve arithmetic it
	// is meaningless, and it is what the length bound exists to catch.
	oversized := new(big.Int).Lsh(big.NewInt(1), 8*33)

	_, err = parseJWK(jwk{Kty: "EC", Crv: "P-256", X: b64(oversized), Y: b64(k.Y)})
	if err == nil {
		t.Fatal("an x coordinate wider than the field must be refused")
	}
}

func TestParseJWK_supportsEveryCurveItClaims(t *testing.T) {
	// The provider chooses the curve, so all three advertised ones have to work
	// — only P-256 was exercised before.
	for name, curve := range map[string]elliptic.Curve{
		"P-256": elliptic.P256(),
		"P-384": elliptic.P384(),
		"P-521": elliptic.P521(),
	} {
		t.Run(name, func(t *testing.T) {
			k, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate %s key: %v", name, err)
			}
			got, err := parseJWK(jwk{Kty: "EC", Crv: name, X: b64(k.X), Y: b64(k.Y)})
			if err != nil {
				t.Fatalf("%s must be supported, got: %v", name, err)
			}
			pub, ok := got.(*ecdsa.PublicKey)
			if !ok || pub.Curve != curve {
				t.Fatalf("%s parsed into the wrong key type or curve: %T", name, got)
			}
		})
	}
}

func TestParseJWK_rejectsAnUnknownCurve(t *testing.T) {
	_, err := parseJWK(jwk{Kty: "EC", Crv: "P-999", X: b64(big.NewInt(1)), Y: b64(big.NewInt(1))})
	if err == nil {
		t.Fatal("an unknown curve must be refused rather than defaulted")
	}
}
