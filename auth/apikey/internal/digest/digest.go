// Package digest computes the stored hash of an API key.
package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Hash computes the keyed HMAC-SHA256 hex digest of key under secret.
func Hash(secret []byte, key string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}
