// Package pkce generates the unguessable state, nonce and PKCE verifier of an authorization request
// and derives the S256 code challenge from a verifier (RFC 7636).
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// randomTokenBytes is the entropy of state, nonce, and the PKCE verifier.
// 32 bytes (256 bits) is comfortably above any guessing attack.
const randomTokenBytes = 32

// readRandom is the entropy source; tests replace it to exercise the failure
// path, which crypto/rand does not produce on demand.
var readRandom = rand.Read

// RandomURLToken returns base64url(no padding) over randomTokenBytes of CSPRNG
// output — used for state, nonce, and the PKCE code_verifier (all of which must
// be unguessable and URL-safe).
func RandomURLToken() (string, error) {
	b := make([]byte, randomTokenBytes)
	if _, err := readRandom(b); err != nil {
		return "", fmt.Errorf("oauth: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge derives the S256 PKCE code_challenge from a verifier
// (RFC 7636 §4.2): BASE64URL(SHA256(verifier)). S256 is the only method used;
// "plain" is never offered, so a downgrade cannot strip the protection.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
