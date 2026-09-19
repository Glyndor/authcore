// Load-only tests for Config.RequireExistingKeys.
//
// Every case here drives authcore.New on a KeysDir shaped for a particular
// scenario. The point of the suite is to pin what the flag does and does not
// change about that call: which errors wrap ErrInvalidConfig and which wrap
// ErrKeyManager, whether the directory listing is byte-for-byte the same
// before and after, and that the existing default behaviour still applies
// when the flag is left at its zero value.

package authcore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// TestLoadOnlyMissingKeysDirReturnsErrInvalidConfig pins the load-only
// rejection of a KeysDir that does not exist: the failure must surface as
// ErrInvalidConfig (so existing config-error handling applies), the message
// must name the path so the operator can see what was missing, and the
// directory must remain missing afterwards (New must not have created it).
func TestLoadOnlyMissingKeysDirReturnsErrInvalidConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = missing
	cfg.RequireExistingKeys = true

	_, err := authcore.New(cfg)
	if err == nil {
		t.Fatal("expected an error for a missing KeysDir in load-only mode, got nil")
	}
	if !errors.Is(err, authcore.ErrInvalidConfig) {
		t.Errorf("expected the error to wrap ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error should name the missing path %q, got: %v", missing, err)
	}
	if _, statErr := os.Stat(missing); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the missing path must still be missing after New refused, stat gave: %v", statErr)
	}
}

// TestLoadOnlyEmptyKeysDirFailsWithErrKeyManager pins the load-only refusal
// of an empty but existing KeysDir. The failure must wrap ErrKeyManager
// (the same envelope the disk store already uses for an unreadable key), the
// message must name all three files so the operator can act on it, and the
// directory must be left empty: New must not have written a .gitignore, a
// metadata.json or anything else.
func TestLoadOnlyEmptyKeysDirFailsWithErrKeyManager(t *testing.T) {
	dir := t.TempDir()
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	_, err := authcore.New(cfg)
	if err == nil {
		t.Fatal("expected an error for an empty KeysDir in load-only mode, got nil")
	}
	if !errors.Is(err, authcore.ErrKeyManager) {
		t.Errorf("expected the error to wrap ErrKeyManager, got %v", err)
	}
	for _, name := range []string{
		"ed25519_private.pem",
		"ed25519_public.pem",
		"refresh_secret.key",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should list %q, got: %v", name, err)
		}
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("reading KeysDir after a failed New: %v", readErr)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("load-only New must leave the directory empty, found: %v", names)
	}
}

// TestLoadOnlyPartialKeysDirFailsWithErrKeyManager pins the load-only refusal
// of a directory that holds two of the three key files. The message must
// name refresh_secret.key (the file that was deleted), must tell the operator
// to restore it, and must not contain the word "delete": regenerating that
// file would invalidate every stored hash and every auth/field column. The
// directory listing must be identical before and after.
func TestLoadOnlyPartialKeysDirFailsWithErrKeyManager(t *testing.T) {
	dir := t.TempDir()
	seedDir(t, dir)
	if err := os.Remove(filepath.Join(dir, "refresh_secret.key")); err != nil {
		t.Fatalf("remove refresh_secret.key: %v", err)
	}
	before := snapshotDir(t, dir)

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	_, err := authcore.New(cfg)
	if err == nil {
		t.Fatal("expected an error for a partial KeysDir in load-only mode, got nil")
	}
	if !errors.Is(err, authcore.ErrKeyManager) {
		t.Errorf("expected the error to wrap ErrKeyManager, got %v", err)
	}
	if !strings.Contains(err.Error(), "refresh_secret.key") {
		t.Errorf("error should name the missing file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Errorf("error should tell the operator to restore, got: %v", err)
	}
	if strings.Contains(err.Error(), "delete") {
		t.Errorf("error must not contain 'delete', got: %v", err)
	}
	assertDirUnchanged(t, dir, before)
}

// TestLoadOnlyCompleteKeysDirLoadsUntouched pins the happy path of the
// load-only mode: a directory that already holds the three key files is
// loaded, and the directory listing (names, sizes, mod times, modes) is
// byte-for-byte identical before and after the call. The signing key id
// must match the one the standard New produced on the same directory, so
// the load is reading the same bytes New wrote.
func TestLoadOnlyCompleteKeysDirLoadsUntouched(t *testing.T) {
	dir := t.TempDir()
	km1 := seedDir(t, dir)
	before := snapshotDir(t, dir)

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New on a complete KeysDir in load-only mode: %v", err)
	}
	if ac.Keys().KeyID() != km1.KeyID() {
		t.Errorf("key id mismatch: load-only=%q, seeded=%q", ac.Keys().KeyID(), km1.KeyID())
	}
	assertDirUnchanged(t, dir, before)
}

// TestLoadOnlyCompleteKeysDirNoMetadataLoads pins the read-only contract for
// the metadata.json file: a directory that holds the three key files but no
// metadata.json loads successfully, and metadata.json must still be absent
// after the call. The pre-metadata layout is adopted on the next start, and
// load-only mode must not regress that.
func TestLoadOnlyCompleteKeysDirNoMetadataLoads(t *testing.T) {
	dir := t.TempDir()
	seedDir(t, dir)
	if err := os.Remove(filepath.Join(dir, "metadata.json")); err != nil {
		t.Fatalf("strip metadata: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New on a complete, metadata-less directory in load-only mode: %v", err)
	}
	if ac.Keys() == nil {
		t.Fatal("Keys() returned nil after a successful load-only load")
	}

	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("load-only mode must not write metadata.json, stat gave: %v", err)
	}
}

// TestLoadOnlyReadOnlyKeysDirLoads pins that load-only mode loads from a
// read-only directory. The check is skipped on Windows (Unix permission bits
// do not apply) and when running as root (root bypasses them).
func TestLoadOnlyReadOnlyKeysDirLoads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only enforcement relies on Unix permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses Unix directory permission bits")
	}

	dir := t.TempDir()
	seedDir(t, dir)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New on a 0500 KeysDir in load-only mode: %v", err)
	}
	if ac.Keys() == nil {
		t.Fatal("Keys() returned nil after a successful load-only load")
	}
}

// TestLoadOnlyCorruptMetadataFailsWithErrKeyManager pins the load-only
// refusal of a complete directory whose metadata.json is zero bytes. The
// failure must wrap ErrKeyManager (the same envelope the loaders already
// use for unparseable metadata) and must surface the recovery advice that
// the metadata loader prints.
func TestLoadOnlyCorruptMetadataFailsWithErrKeyManager(t *testing.T) {
	dir := t.TempDir()
	seedDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), nil, 0600); err != nil {
		t.Fatalf("zero metadata: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true

	_, err := authcore.New(cfg)
	if err == nil {
		t.Fatal("expected an error for a corrupt metadata.json in load-only mode, got nil")
	}
	if !errors.Is(err, authcore.ErrKeyManager) {
		t.Errorf("expected the error to wrap ErrKeyManager, got %v", err)
	}
}

// TestLoadOnlyKeyStoreBypassesMissingKeysDir pins that the load-only check
// on KeysDir is bypassed when Config.KeyStore is set. The custom store
// neither writes to KeysDir nor reads from it, so the field has nothing to
// gate, and the missing KeysDir must not be created.
func TestLoadOnlyKeyStoreBypassesMissingKeysDir(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pair: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("gen secret: %v", err)
	}

	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("NewKeyStoreFromKeys: %v", err)
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = missing
	cfg.KeyStore = ks
	cfg.RequireExistingKeys = true

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New with KeyStore and load-only and missing KeysDir: %v", err)
	}
	if ac.Keys() == nil {
		t.Fatal("Keys() returned nil after a successful load-only with KeyStore")
	}
	if _, statErr := os.Stat(missing); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the missing KeysDir must not be created when KeyStore is in use, stat gave: %v", statErr)
	}
}

// TestLoadOnlyDefaultBehaviourGeneratesAsBefore pins that the existing
// default (RequireExistingKeys at its zero value) still generates a fresh
// key set on an empty KeysDir. This is the regression guard: the load-only
// flag must not change anything for callers that do not opt in.
func TestLoadOnlyDefaultBehaviourGeneratesAsBefore(t *testing.T) {
	dir := t.TempDir()

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	// cfg.RequireExistingKeys is the zero value: false.

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New on an empty dir with default config: %v", err)
	}
	if ac.Keys() == nil {
		t.Fatal("Keys() returned nil after the default generated a set")
	}
	for _, name := range []string{
		"ed25519_private.pem",
		"ed25519_public.pem",
		"refresh_secret.key",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("default New should have generated %q, stat: %v", name, err)
		}
	}
}
