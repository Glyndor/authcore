package keymanager

import (
	"crypto/ed25519"
	"fmt"
)

// ValidateMaterial reports whether priv, pub and secret form usable key
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
func ValidateMaterial(priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte) error {
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
	if l := len(secret); l != refreshSecretLen {
		return fmt.Errorf("refresh secret has wrong length: got %d, want %d", l, refreshSecretLen)
	}
	return nil
}

// FromKeys builds an in-memory KeyManager from already-loaded key material,
// touching no filesystem. It is the backend for a non-disk KeyStore (keys
// sourced from a secret manager, environment, or KMS).
//
// It validates that pub is the public half of priv and that secret is the
// expected length, then derives the key id. The returned manager has no
// directory; Dir returns "".
//
// The three input slices are copied before the manager stores them: a caller
// that wipes its own buffers once FromKeys returns must not blank the live
// material, and a caller that reuses the same buffer across concurrent
// KeyStore loads must not race with a still-running token verification.
func FromKeys(priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte) (*KeyManager, error) {
	if err := ValidateMaterial(priv, pub, secret); err != nil {
		return nil, err
	}

	privCopy := make(ed25519.PrivateKey, len(priv))
	copy(privCopy, priv)
	pubCopy := make(ed25519.PublicKey, len(pub))
	copy(pubCopy, pub)
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &KeyManager{
		privateKey:    privCopy,
		publicKey:     pubCopy,
		refreshSecret: secretCopy,
		keyID:         computeKeyID(pubCopy),
	}, nil
}

// FromPEM builds an in-memory KeyManager from PEM-encoded key material — a
// PKCS#8 private key, a PKIX public key, and the raw 32-byte refresh secret.
// Use it to source keys from environment variables or a secret store that hands
// out PEM blocks.
//
// FromKeys copies the refresh secret, so a caller that wipes its source buffer
// once FromPEM returns does not blank the live material. The PEM blocks
// themselves decode into freshly allocated key slices.
func FromPEM(privatePEM, publicPEM, refreshSecret []byte) (*KeyManager, error) {
	priv, err := decodeEd25519PrivatePEM(privatePEM, "private key input")
	if err != nil {
		return nil, err
	}
	pub, err := decodeEd25519PublicPEM(publicPEM, "public key input")
	if err != nil {
		return nil, err
	}
	return FromKeys(priv, pub, refreshSecret)
}
