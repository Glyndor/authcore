package authcore

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// KeyStore sources authcore's cryptographic key material (the Ed25519 signing
// pair and the HMAC refresh secret).
//
// The default is disk: New generates and loads PEM files under Config.KeysDir.
// Set Config.KeyStore to override that — for example to source keys from a
// secret manager, environment variables, or KMS, which is the right fit for
// serverless or disk-averse deployments where a mounted volume is awkward.
//
// Implementations are consulted once, at New time. The returned Keys must be
// stable for the lifetime of the AuthCore instance.
type KeyStore interface {
	// Load returns the key material, or an error if it cannot be obtained or
	// fails validation.
	Load() (Keys, error)
}

// diskKeyStore is the default KeyStore: it generates the key files on first run
// and loads them on subsequent runs, under dir. It preserves the zero-config
// secure-disk behaviour when Config.KeyStore is not set.
type diskKeyStore struct {
	dir string
	log Logger
}

func (d diskKeyStore) Load() (Keys, error) {
	return keymanager.New(d.dir, d.log)
}

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
// It validates that pub is the public half of priv and that refreshSecret is
// 32 bytes. Assign the result to Config.KeyStore.
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
