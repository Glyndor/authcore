package oauth

import "testing"

// FuzzParseJWK drives the JWK -> public key decoder with arbitrary field values.
// A JWKS document is parsed into key structures (big integers, EC point checks),
// so the decoder must never panic — only return a key or an error.
func FuzzParseJWK(f *testing.F) {
	f.Add("0vx7agoebGcQSuuPiLJXZ", "AQAB", "", "", "")
	f.Add("", "", "P-256", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
	f.Add("", "", "", "", "")
	f.Add("AQAB", "AQAB", "P-999", "AQAB", "AQAB")

	f.Fuzz(func(t *testing.T, n, e, crv, x, y string) {
		for _, kty := range []string{"RSA", "EC", "oct", ""} {
			_, _ = parseJWK(jwk{Kty: kty, N: n, E: e, Crv: crv, X: x, Y: y})
		}
	})
}
