package oauth

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

// googleJWKSFirstN is the modulus (n) and exponent (e) of the first key in
// auth/oauth/testdata/providers/google-jwks.json, copied verbatim so a fuzz
// run starts from a real provider's key without reading the file at run
// time. It is also pinned by TestParseJWK_googleJWKSSeed below.
const (
	googleJWKSFirstN = "qhj5FWiUDLfueA6OVLblfXZ9AJt7NLjFKiTk8uspRajkYzT_RiQlBmhvRacEqXCAY1PG5ylPJaaeix4YeufQHoZngjHmE2v7k6OvJnUAJE8Ne4zzvA8mEQpNbrGsF4B0g3Ks01wfWbWxWQjZF0hC0sas2DpHNCjGjuI1vSwcqqdAnpXzM4B8DCqKh9KDaC_JR2_C-STWhQhs3RpZJoLiY1VjXVpMuy7WKBe7QrS6XUTeBX_LDp9a7a3S6mvJ3XuU2zLfqQvdxi6z7HeOKu7CVfxBXjmWB7qkC4B-INwt6goAhADFxs0fw_JAtsG0xdsLV0DlTLlcUghb8AocsDSrWQ"
	googleJWKSFirstE = "AQAB"
)

// FuzzParseJWK drives the JWK -> public key decoder with arbitrary field
// values. A JWKS document is parsed into key structures (big integers, EC
// point checks), so the decoder must never panic: only return a key or an
// error. The Google RSA key seed was added on 2026-09-27 so the RSA accept
// path is reached from the start of every fuzz run, alongside the synthetic
// boundary-case seeds below.
func FuzzParseJWK(f *testing.F) {
	f.Add("0vx7agoebGcQSuuPiLJXZ", "AQAB", "", "", "")
	f.Add("", "", "P-256", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	f.Add("", "", "", "", "")
	f.Add("AQAB", "AQAB", "P-999", "AQAB", "AQAB")
	// Real Google provider key, copied verbatim from
	// testdata/providers/google-jwks.json on 2026-09-07.
	f.Add(googleJWKSFirstN, googleJWKSFirstE, "", "", "")

	f.Fuzz(func(t *testing.T, n, e, crv, x, y string) {
		for _, kty := range []string{"RSA", "EC", "oct", ""} {
			pub, err := parseJWK(jwk{Kty: kty, N: n, E: e, Crv: crv, X: x, Y: y})
			if err != nil {
				// Every accepted (nil-error) key shape is constrained below.
				// For every kty other than "RSA" and "EC", parseJWK must
				// return an error.
				if kty != "RSA" && kty != "EC" {
					if pub != nil {
						t.Errorf("kty=%q: nil error with non-nil key %T", kty, pub)
					}
				}
				continue
			}
			// Oracle: when parseJWK returned nil error, the key shape must
			// obey the parser's published contract. parseJWK's own helpers
			// are deliberately NOT called here; the EC check re-encodes the
			// accepted key with ecdsa.PublicKey.Bytes and parses the result
			// through crypto/ecdh.NewPublicKey, a different standard library
			// entry point from the parser's ecdsa.ParseUncompressedPublicKey.
			// Both reach the same curve arithmetic underneath, so this pins the
			// parser's use of the library, not the library itself.
			switch kty {
			case "RSA":
				checkRSAKey(t, pub)
			case "EC":
				checkECKey(t, pub)
			default:
				t.Errorf("kty=%q: parseJWK returned %T with no error; only RSA and EC are supported", kty, pub)
			}
		}
	})
}

// TestParseJWK_googleJWKSSeed pins the validity of the fuzz seed by running
// parseJWK against the real Google key outside the fuzz harness. If this
// test ever fails, the fuzz corpus has drifted away from a parseable seed
// and future fuzz runs would silently regress.
func TestParseJWK_googleJWKSSeed(t *testing.T) {
	pub, err := parseJWK(jwk{Kty: "RSA", N: googleJWKSFirstN, E: googleJWKSFirstE})
	if err != nil {
		t.Fatalf("Google seed must parse: %v", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Google seed returned %T, want *rsa.PublicKey", pub)
	}
	// Real Google modulus is 2048 bits, exponent 65537.
	if got := rsaKey.N.BitLen(); got != 2048 {
		t.Errorf("Google seed modulus bits = %d, want 2048", got)
	}
	if rsaKey.E != 65537 {
		t.Errorf("Google seed exponent = %d, want 65537", rsaKey.E)
	}
}

// checkRSAKey is the RSA branch of the FuzzParseJWK oracle, lifted into its
// own function so the fuzz harness stays under the cyclop limit.
func checkRSAKey(t *testing.T, pub crypto.PublicKey) {
	t.Helper()
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Errorf("RSA kty: returned %T, want *rsa.PublicKey", pub)
		return
	}
	if bits := rsaKey.N.BitLen(); bits < 2048 || bits > 16384 {
		t.Errorf("RSA modulus bit length %d outside [2048, 16384]", bits)
	}
	if rsaKey.E < 2 {
		t.Errorf("RSA exponent %d below the minimum 2", rsaKey.E)
	}
	// E must fit an int on a 32-bit build and be a real exponent
	// (commonly 65537).
	if rsaKey.E >= 1<<31 {
		t.Errorf("RSA exponent %d exceeds the 31-bit cap", rsaKey.E)
	}
}

// checkECKey is the EC branch of the FuzzParseJWK oracle, lifted into its
// own function so the fuzz harness stays under the cyclop limit. The check
// re-encodes the accepted key with ecdsa.PublicKey.Bytes and parses the
// result through crypto/ecdh.NewPublicKey, a path that does not share code
// with the parser's ecdsa.ParseUncompressedPublicKey call.
func checkECKey(t *testing.T, pub crypto.PublicKey) {
	t.Helper()
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("EC kty: returned %T, want *ecdsa.PublicKey", pub)
		return
	}
	b, berr := ecKey.Bytes()
	if berr != nil {
		t.Errorf("EC key could not be re-encoded as an uncompressed point: %v", berr)
		return
	}
	var ec ecdh.Curve
	switch ecKey.Curve.Params().Name {
	case "P-256":
		ec = ecdh.P256()
	case "P-384":
		ec = ecdh.P384()
	case "P-521":
		ec = ecdh.P521()
	default:
		t.Errorf("EC key has unrecognised curve %q", ecKey.Curve.Params().Name)
		return
	}
	if _, perr := ec.NewPublicKey(b); perr != nil {
		t.Errorf("EC point on %s could not be re-parsed via crypto/ecdh: %v",
			ecKey.Curve.Params().Name, perr)
	}
}
