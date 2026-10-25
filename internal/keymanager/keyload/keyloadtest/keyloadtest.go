// Package keyloadtest is the test-side support for keyload and its loadonly
// subpackage: a silent and a recording logger, and a writer that drops a
// known-good key set into a directory. It imports no production keyload code,
// so either package's tests can use it. Only _test.go files import it.
package keyloadtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// SilentLog discards everything it is given.
type SilentLog struct{}

// Info discards the message.
func (SilentLog) Info(string, ...any) {}

// Warn discards the message.
func (SilentLog) Warn(string, ...any) {}

// Recorder keeps the formatted warnings it is given.
type Recorder struct{ Warnings []string }

// Info discards the message.
func (r *Recorder) Info(string, ...any) {}

// Warn records the formatted message.
func (r *Recorder) Warn(msg string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(msg, args...))
}

// KeySet is the key material WriteSet put on disk.
type KeySet struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
}

// must returns v, or panics when err is set. The crypto calls below cannot
// fail with the system random source, so they are not worth a branch each.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// WriteSet drops a known-good trio into dir and returns the keys it holds.
func WriteSet(t testing.TB, dir string) KeySet {
	t.Helper()
	pub, priv := must2(ed25519.GenerateKey(rand.Reader))
	secret := make([]byte, layout.RefreshSecretLen)
	must(rand.Read(secret))
	Put(t, dir, layout.FilePrivateKey, must(pemcodec.EncodePrivateKeyPEM(priv)), 0600)
	Put(t, dir, layout.FilePublicKey, must(pemcodec.EncodePublicKeyPEM(pub)), 0644)
	Put(t, dir, layout.FileRefreshSecret, []byte(hex.EncodeToString(secret)+"\n"), 0600)
	return KeySet{priv, pub, secret}
}

// must2 is must for the two-value key generation call.
func must2(pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) (ed25519.PublicKey, ed25519.PrivateKey) {
	must(0, err)
	return pub, priv
}

// Put writes data to dir/name with perm.
func Put(t testing.TB, dir, name string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, perm); err != nil {
		t.Fatal(err)
	}
}
