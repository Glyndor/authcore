package authcore

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// staticKeyStore serves pre-built, in-memory key material. It never touches
// the filesystem.
type staticKeyStore struct {
	keys Keys
}

func (s staticKeyStore) Load() (Keys, error) {
	return s.keys, nil
}

// NewKeyStoreFromKeys returns a KeyStore backed by in-memory Ed25519 material,
// touching no filesystem. Use it to inject keys obtained from a secret manager
// or KMS at startup.
//
// It validates that priv is a well-formed Ed25519 private key, that pub is
// its public half, and that refreshSecret is 32 bytes. Assign the result to
// Config.KeyStore.
func NewKeyStoreFromKeys(priv ed25519.PrivateKey, pub ed25519.PublicKey, refreshSecret []byte) (KeyStore, error) {
	km, err := keymanager.FromKeys(priv, pub, refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyManager, err)
	}
	return staticKeyStore{keys: km}, nil
}

// NewKeyStoreFromPEM returns a KeyStore from PEM-encoded material: a PKCS#8
// private key, a PKIX public key, and the raw 32-byte refresh secret. This is
// the convenient form when keys arrive as PEM strings from environment
// variables or a secret store.
//
// Assign the result to Config.KeyStore.
func NewKeyStoreFromPEM(privatePEM, publicPEM, refreshSecret []byte) (KeyStore, error) {
	km, err := keymanager.FromPEM(privatePEM, publicPEM, refreshSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyManager, err)
	}
	return staticKeyStore{keys: km}, nil
}
