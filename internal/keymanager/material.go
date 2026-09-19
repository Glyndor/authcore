package keymanager

import (
	"crypto/ed25519"
	"fmt"
)

// ValidateMaterial reports whether priv, pub and secret form usable key
// material: an Ed25519 private key of ed25519.PrivateKeySize bytes, a public
// key of ed25519.PublicKeySize bytes that is the public half of priv, and a
// refresh secret of exactly 32 bytes. It returns nil when all of that holds,
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
func FromKeys(priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte) (*KeyManager, error) {
	if err := ValidateMaterial(priv, pub, secret); err != nil {
		return nil, err
	}

	return &KeyManager{
		privateKey:    priv,
		publicKey:     pub,
		refreshSecret: secret,
		keyID:         computeKeyID(pub),
	}, nil
}

// FromPEM builds an in-memory KeyManager from PEM-encoded key material — a
// PKCS#8 private key, a PKIX public key, and the raw 32-byte refresh secret.
// Use it to source keys from environment variables or a secret store that hands
// out PEM blocks.
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
