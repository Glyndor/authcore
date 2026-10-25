// Package material holds the rules about in-memory key material: what makes a
// private key, a public key and a refresh secret a usable set, and how the key
// identifier is derived from the public key.
package material

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Validate reports whether priv, pub and secret form usable key
// material: an Ed25519 private key of ed25519.PrivateKeySize bytes whose
// second half is the public key its seed derives, a public key of
// ed25519.PublicKeySize bytes that is the public half of priv, and a refresh
// secret of exactly 32 bytes. It returns nil when all of that holds,
// and otherwise an error naming the first rule that failed. The error never
// contains key bytes.
//
// Keep every rule about in-memory material here. FromKeys, FromPEM and the
// root package's check on a consumer-supplied KeyStore all call it, so that a
// custom store is held to the same rules as the built-in ones.
func Validate(priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte) error {
	if l := len(priv); l != ed25519.PrivateKeySize {
		return fmt.Errorf("private key has wrong length: got %d, want %d", l, ed25519.PrivateKeySize)
	}
	if l := len(pub); l != ed25519.PublicKeySize {
		return fmt.Errorf("public key has wrong length: got %d, want %d", l, ed25519.PublicKeySize)
	}
	// Derive the key from its seed. Do not rely on priv.Public() alone: it
	// reads back bytes 32..64 of priv and derives nothing. A private key made
	// of one key's seed and another key's public half, passed with that other
	// public key, satisfied the comparison below when measured on
	// 2026-09-18, and ed25519.Sign then produced signatures that did not
	// verify, so every token issued would have been refused.
	//
	// Keep this after the length check: Seed panics on a key shorter than its
	// 32-byte seed.
	if !ed25519.NewKeyFromSeed(priv.Seed()).Equal(priv) {
		return fmt.Errorf("private key is inconsistent: its second half is not the public key its seed derives")
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return fmt.Errorf("public key does not match private key")
	}
	if l := len(secret); l != layout.RefreshSecretLen {
		return fmt.Errorf("refresh secret has wrong length: got %d, want %d", l, layout.RefreshSecretLen)
	}
	return nil
}

// KeyID derives a stable identifier from a public key.
// It returns the first 8 bytes of the SHA-256 digest of the raw public key
// bytes, hex-encoded (16 lowercase characters). The value changes automatically
// when the key is rotated, making it suitable as a JOSE "kid" header value.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}
