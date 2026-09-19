package authcore

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"

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

// validateLoadedKeys enforces the KeyStore contract on what a store returned.
//
// Do not skip it for the built-in stores: it is the single place where New
// learns that the material is usable, and the accessor calls are cheap. Before
// it existed, a store returning (nil, nil) passed New and the process
// panicked with a nil dereference on the first token it signed (#348).
func validateLoadedKeys(keys Keys) error {
	if keys == nil {
		return errors.New("KeyStore.Load returned nil Keys with a nil error; " +
			"a store that finds no key material must return an error")
	}
	if isNilValue(keys) {
		return fmt.Errorf("KeyStore.Load returned a nil %T wrapped in a non-nil Keys; "+
			"return an error when there is no key material", keys)
	}
	if err := keymanager.ValidateMaterial(keys.PrivateKey(), keys.PublicKey(), keys.RefreshSecret()); err != nil {
		return fmt.Errorf("KeyStore.Load returned unusable key material: %w", err)
	}
	return nil
}

// isNilValue reports whether the dynamic value inside a non-nil interface is
// itself nil. A plain "== nil" comparison cannot see this case, because an
// interface holding a typed nil pointer is not equal to nil.
func isNilValue(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
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
	if d.requireExisting {
		return keymanager.Load(d.dir, d.log)
	}
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
