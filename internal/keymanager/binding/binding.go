// Package binding ties the refresh secret to the key pair it was generated
// with. metadata.json records a keyed hash of the public key, keyed with the
// secret, so a refresh_secret.key taken from another set (a restore of one
// file from the wrong backup, a partial overwrite) is recognised without the
// metadata ever holding anything that reveals the secret.
package binding

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// label separates this use of the secret from every other one (refresh-token
// hashing, field-key derivation), so the value cannot be replayed as one.
const label = "authcore/keymanager/secret-binding/v1\x00"

// Compute returns the binding of secret to pub as lowercase hex.
func Compute(pub ed25519.PublicKey, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	mac.Write(pub)
	return hex.EncodeToString(mac.Sum(nil))
}

// Matches reports whether recorded is the binding of secret to pub. The
// comparison does not depend on where the two values first differ.
func Matches(recorded string, pub ed25519.PublicKey, secret []byte) bool {
	return hmac.Equal([]byte(recorded), []byte(Compute(pub, secret)))
}
