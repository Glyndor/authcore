// Package refreshhash computes and compares the HMAC-SHA256 digest under which
// the application stores a refresh token.
package refreshhash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Compute returns the HMAC-SHA256 hex digest of token keyed with secret.
func Compute(token string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// Equal reports whether storedHash is the digest of token under secret. The
// comparison runs in constant time.
func Equal(token, storedHash string, secret []byte) bool {
	computed := Compute(token, secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}
