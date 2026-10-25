package authcore

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Glyndor/authcore/internal/keymanager"
	"github.com/Glyndor/authcore/internal/keystore"
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
//
// # Contract for custom implementations
//
// Load must return either usable material and a nil error, or a non-nil error.
// A lookup that succeeded and found nothing is an error: never return
// (nil, nil), and never return a nil pointer wrapped in a non-nil Keys, which
// is what "var k *myKeys; return k, nil" produces.
//
// New checks what Load returned before anything uses it, with the same rules
// that NewKeyStoreFromKeys applies:
//
//   - PrivateKey is ed25519.PrivateKeySize (64) bytes: the seed followed by
//     the public key that seed derives, as crypto/ed25519 produces it. A bare
//     32-byte seed is refused; expand it with ed25519.NewKeyFromSeed first.
//   - PublicKey is ed25519.PublicKeySize (32) bytes and is the public half of
//     PrivateKey.
//   - RefreshSecret is exactly 32 bytes.
//
// Material that breaks any of these makes New fail with an error that wraps
// ErrKeyManager and names the rule. New calls the accessors on the returned
// Keys for this check, so they must be safe to call as soon as Load returns.
type KeyStore interface {
	// Load returns the key material, or an error if it cannot be obtained or
	// fails validation. It never returns nil Keys together with a nil error.
	Load() (Keys, error)
}

// diskKeyStore is the default KeyStore: it generates the key files on first run
// and loads them on subsequent runs, under dir. It preserves the zero-config
// secure-disk behaviour when Config.KeyStore is not set.
//
// When requireExisting is true, the store never writes: it expects the three
// key files to already be present and refuses to start otherwise. The flag
// is set from Config.RequireExistingKeys; see config.go for the contract.
type diskKeyStore struct {
	dir             string
	log             Logger
	requireExisting bool
}

func (d diskKeyStore) Load() (Keys, error) {
	km, err := keystore.LoadDisk(d.dir, d.log, d.requireExisting)
	if err != nil {
		return nil, err
	}
	return km, nil
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
