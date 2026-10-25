// Package keystore holds the checks and the disk loader behind the root
// package's KeyStore: what New verifies about the material a store returned,
// and how the default disk store reaches the key manager.
package keystore

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// Keys is the read-only view of key material that Validate inspects. It has
// the same method set as the root package's Keys, which satisfies it.
type Keys interface {
	PrivateKey() ed25519.PrivateKey
	PublicKey() ed25519.PublicKey
	RefreshSecret() []byte
	KeyID() string
}

// Logger is the logging surface the key manager reports through. It has the
// same method set as the root package's Logger.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Validate enforces the KeyStore contract on what a store returned.
//
// Do not skip it for the built-in stores: it is the single place where New
// learns that the material is usable, and the accessor calls are cheap. Before
// it existed, a store returning (nil, nil) passed New and the process
// panicked with a nil dereference on the first token it signed (#348).
func Validate(keys Keys) error {
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
	// The kid goes into every token header and selects the verification key.
	// An empty one registered the current key under "", so a token with no
	// kid header verified against it, contrary to what auth/jwt promises.
	if keys.KeyID() == "" {
		return errors.New("KeyStore.Load returned Keys with an empty KeyID; " +
			"return a stable, non-empty identifier for the signing key")
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

// LoadDisk is the default store: it generates the key files on first run and
// loads them on subsequent runs, under dir.
//
// When requireExisting is true it never writes: it expects the three key
// files to already be present and refuses to start otherwise.
func LoadDisk(dir string, log Logger, requireExisting bool) (*keymanager.KeyManager, error) {
	if requireExisting {
		return keymanager.Load(dir, log)
	}
	return keymanager.New(dir, log)
}
