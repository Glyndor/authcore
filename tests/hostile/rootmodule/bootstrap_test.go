// Package rootmodule attacks the bootstrap of the root module: what New
// accepts from a key store and from a key directory.
package rootmodule

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore"
)

type storeFunc func() (authcore.Keys, error)

func (f storeFunc) Load() (authcore.Keys, error) { return f() }

func goodKeys(t *testing.T) authcore.Keys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ks.Load()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// halfKeys has a signing key and nothing else.
type halfKeys struct{ authcore.Keys }

func (halfKeys) RefreshSecret() []byte { return nil }

func newWithStore(t *testing.T, load func() (authcore.Keys, error)) (*authcore.AuthCore, error) {
	t.Helper()
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.KeyStore = storeFunc(load)
	return authcore.New(cfg)
}

// A store that reports a failure is a failed start, even when it hands back
// usable-looking material alongside the error.
func TestHostile_Root_aKeyStoreErrorFailsTheStartEvenWithKeysAttached(t *testing.T) {
	good := goodKeys(t)
	ac, err := newWithStore(t, func() (authcore.Keys, error) { return good, errors.New("vault sealed") })
	if ac != nil || !errors.Is(err, authcore.ErrKeyManager) {
		t.Fatalf("New = %v, %v; want ErrKeyManager and no instance", ac, err)
	}
	if !strings.Contains(err.Error(), "vault sealed") {
		t.Errorf("the store's own reason is lost: %v", err)
	}
}

func TestHostile_Root_aKeyStoreThatBreaksTheContractFailsTheStart(t *testing.T) {
	good := goodKeys(t)
	cases := map[string]func() (authcore.Keys, error){
		"no material, no error": func() (authcore.Keys, error) { return nil, nil },
		"no refresh secret":     func() (authcore.Keys, error) { return halfKeys{good}, nil },
	}
	for name, load := range cases {
		ac, err := newWithStore(t, load)
		if ac != nil || !errors.Is(err, authcore.ErrKeyManager) {
			t.Errorf("%s: New = %v, %v; want ErrKeyManager and no instance", name, ac, err)
		}
	}
	if ac, err := newWithStore(t, func() (authcore.Keys, error) { return good, nil }); err != nil || ac == nil {
		t.Fatalf("control: a sound store must start, got %v", err)
	}
}

// Load-only mode never writes: a missing directory stays missing and an empty
// one is refused instead of being filled with fresh keys.
func TestHostile_Root_loadOnlyModeNeverCreatesKeys(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "keys")
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = missing
	cfg.RequireExistingKeys = true
	if ac, err := authcore.New(cfg); err == nil || ac != nil {
		t.Fatalf("a missing key directory must refuse to start, got %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("load-only mode created the directory: %v", err)
	}

	empty := t.TempDir()
	cfg.KeysDir = empty
	ac, err := authcore.New(cfg)
	if ac != nil || !errors.Is(err, authcore.ErrKeyManager) {
		t.Fatalf("an empty key directory: New = %v, %v; want ErrKeyManager", ac, err)
	}
	if !strings.Contains(err.Error(), "load-only mode") {
		t.Fatalf("the refusal must come from the key directory check, got: %v", err)
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatalf("load-only mode wrote %d file(s) into the directory", len(entries))
	}
}

type infoLog struct {
	mu    sync.Mutex
	lines []string
}

func (*infoLog) Debug(string, ...any) {}
func (*infoLog) Warn(string, ...any)  {}
func (*infoLog) Error(string, ...any) {}
func (l *infoLog) Info(msg string, _ ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, msg)
	l.mu.Unlock()
}

func TestHostile_Root_startIsAnnouncedOnTheConfiguredLogger(t *testing.T) {
	rec := &infoLog{}
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.Logger = rec
	if _, err := authcore.New(cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range rec.lines {
		found = found || strings.Contains(l, "authcore initialised")
	}
	if !found {
		t.Fatalf("info lines = %q, want the initialisation line", rec.lines)
	}
}
