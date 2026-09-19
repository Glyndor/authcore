// Load-only tests for the keymanager entry point Load, in the internal
// keymanager package.
//
// The root package tests cover the public surface (authcore.New). This file
// pins the unit-level behaviour of Load directly so a regression in the
// keymanager cannot hide behind an outer wrapper.

package keymanager_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// TestLoadCorruptMetadataReturnsError pins that a complete directory whose
// metadata.json is zero bytes is refused by Load with the same recovery
// advice the metadata loader prints.
func TestLoadCorruptMetadataReturnsError(t *testing.T) {
	dir := t.TempDir()
	writeValidKeys(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), nil, 0600); err != nil {
		t.Fatalf("write empty metadata: %v", err)
	}

	_, err := keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected an error for a zero-byte metadata.json, got nil")
	}
	if !strings.Contains(err.Error(), "deleting it is safe") {
		t.Errorf("error should mention the safe recovery, got: %v", err)
	}
}

// TestLoadNoMetadataLeavesItAbsent pins Load's read-only contract for a
// directory that holds the three key files but no metadata.json: the load
// succeeds and metadata.json must still be absent afterwards. The byte-for-
// byte stability of every other file on disk is asserted through
// assertBytesUnchanged.
func TestLoadNoMetadataLeavesItAbsent(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "metadata.json")); err != nil {
		t.Fatalf("strip metadata: %v", err)
	}
	beforeBytes := snapshotBytes(t, dir)

	if _, err := keymanager.Load(dir, testLogger{t}); err != nil {
		t.Fatalf("Load must accept a complete, metadata-less directory, got: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load must not write metadata.json, stat gave: %v", err)
	}
	assertBytesUnchanged(t, dir, beforeBytes)
}

// TestLoadRoundTripsExistingKeysWithoutTouchingTheDir pins the happy path
// Load owns: a complete set is loaded, the signing key id matches the one
// New produced on the same directory, and the directory listing is identical
// before and after. Load is a true no-op on disk.
func TestLoadRoundTripsExistingKeysWithoutTouchingTheDir(t *testing.T) {
	dir := t.TempDir()
	km1, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := snapshotListing(t, dir)

	km2, err := keymanager.Load(dir, testLogger{t})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if km2.KeyID() != km1.KeyID() {
		t.Errorf("key id mismatch: Load=%q, New=%q", km2.KeyID(), km1.KeyID())
	}
	assertListingUnchanged(t, dir, before)
}

// TestLoadLoadsFromReadOnlyDirectory pins that Load succeeds on a 0500
// directory. Load never writes, so a read-only mount loads cleanly. The
// check is skipped on Windows (Unix permission bits do not apply) and when
// running as root (root bypasses them).
func TestLoadLoadsFromReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}

	dir, keyID := preMetadataDir(t)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	km, err := keymanager.Load(dir, testLogger{t})
	if err != nil {
		t.Fatalf("Load on a 0500 directory must succeed, got: %v", err)
	}
	if km.KeyID() != keyID {
		t.Errorf("key id = %q, want %q", km.KeyID(), keyID)
	}
}

// TestLoadEmptyDirectoryIsRefusedWithoutWriting pins the load-only refusal
// of an empty directory: the failure must name the load-only mode, must list
// all three missing files so the operator can act on it, and must not
// suggest deletion (regenerating refresh_secret.key would invalidate every
// stored hash and every auth/field column). The directory listing must be
// identical before and after.
func TestLoadEmptyDirectoryIsRefusedWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	before := snapshotListing(t, dir)

	_, err := keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("Load on an empty directory must fail")
	}
	if !strings.Contains(err.Error(), "not complete in load-only mode") {
		t.Errorf("error should name the load-only mode, got: %v", err)
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
	if strings.Contains(err.Error(), "delete") {
		t.Errorf("error must not suggest delete, got: %v", err)
	}
	assertListingUnchanged(t, dir, before)
}

// TestLoadPartialDirectoryIsRefusedWithoutTouchingIt pins the load-only
// refusal of a directory that holds two of the three key files: the
// failure must name refresh_secret.key, must tell the operator to restore
// it, and must not suggest deletion. The directory listing must be
// identical before and after.
func TestLoadPartialDirectoryIsRefusedWithoutTouchingIt(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "refresh_secret.key")); err != nil {
		t.Fatalf("remove refresh_secret.key: %v", err)
	}
	before := snapshotListing(t, dir)

	_, err := keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("Load on a partial directory must fail")
	}
	if !strings.Contains(err.Error(), "refresh_secret.key") {
		t.Errorf("error should name the missing file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Errorf("error should tell the operator to restore, got: %v", err)
	}
	if strings.Contains(err.Error(), "delete") {
		t.Errorf("error must not suggest delete, got: %v", err)
	}
	assertListingUnchanged(t, dir, before)
}

// TestLoadMissingDirectoryReturnsUsefulError pins the load-only behaviour
// for a KeysDir that does not exist: the failure must say the directory
// does not exist and must tell the operator how to recover by provisioning
// the three key files.
func TestLoadMissingDirectoryReturnsUsefulError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := keymanager.Load(missing, testLogger{t})
	if err == nil {
		t.Fatal("Load on a missing directory must fail")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should say the directory does not exist, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Provision") {
		t.Errorf("error should tell the operator how to recover, got: %v", err)
	}
}

// TestLoadRefusesAFileWhereTheDirectoryShouldBe pins the rejection of a
// KeysDir whose path resolves to a regular file: Load must name the path
// and "not a directory" in the error so the operator can act, and must
// leave the file's bytes unchanged. Load is a read-only path; touching the
// file would have destroyed the operator's payload on the way out.
func TestLoadRefusesAFileWhereTheDirectoryShouldBe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir")
	payload := []byte("a regular file at the keys path\n")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := keymanager.Load(path, testLogger{t})
	if err == nil {
		t.Fatal("Load must refuse a regular file at KeysDir")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not a directory") {
		t.Errorf("error should call out 'not a directory', got: %v", err)
	}
	if !strings.Contains(msg, path) {
		t.Errorf("error should name the path %q, got: %v", path, err)
	}

	got, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read file after Load: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("Load must not modify the file: before=%q after=%q", payload, got)
	}
}

// TestLoadRefusesASymlinkLoopAtAKeyName pins the failure surface inspect
// reaches on a self-referential symlink: os.Stat follows links and
// returns ELOOP, which inspect surfaces as the "inspecting" classification
// error and inspectKeySet forwards to Load. The directory listing (names
// and sizes) must be identical before and after the call. Skipped on
// Windows where symlinks behave differently.
func TestLoadRefusesASymlinkLoopAtAKeyName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}

	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pubPath := filepath.Join(dir, "ed25519_public.pem")
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("strip pub: %v", err)
	}
	if err := os.Symlink(pubPath, pubPath); err != nil {
		t.Fatalf("self-symlink: %v", err)
	}
	before := snapshotListing(t, dir)

	_, err := keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("Load must fail on a symlink loop at a key filename")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error should come from inspect, got: %v", err)
	}

	after := snapshotListing(t, dir)
	if len(before) != len(after) {
		t.Fatalf("entry count changed: before=%d after=%d", len(before), len(after))
	}
	for i, b := range before {
		a := after[i]
		if a.name != b.name || a.size != b.size {
			t.Fatalf("entry %d changed: before=%+v after=%+v", i, b, a)
		}
	}
}

// TestLoadRefusesAMalformedRefreshSecret pins the rejection of a complete
// directory whose refresh_secret.key is not hex: Load fails with a message
// that names "refresh secret" so the operator can act on it, and the
// private and public key files must be byte-identical before and after.
// The malformed secret is left alone on disk; only the two key files are
// checked.
func TestLoadRefusesAMalformedRefreshSecret(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	privPath := filepath.Join(dir, "ed25519_private.pem")
	pubPath := filepath.Join(dir, "ed25519_public.pem")
	privBefore, err := os.ReadFile(privPath) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	pubBefore, err := os.ReadFile(pubPath) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}

	garbage := append(bytes.Repeat([]byte("z"), 64), '\n')
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), garbage, 0600); err != nil {
		t.Fatalf("overwrite refresh_secret.key: %v", err)
	}

	_, err = keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("Load must fail when refresh_secret.key is not hex")
	}
	if !strings.Contains(err.Error(), "refresh secret") {
		t.Errorf("error should name 'refresh secret', got: %v", err)
	}

	privAfter, err := os.ReadFile(privPath) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read priv after Load: %v", err)
	}
	if string(privAfter) != string(privBefore) {
		t.Fatalf("ed25519_private.pem was rewritten")
	}
	pubAfter, err := os.ReadFile(pubPath) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read pub after Load: %v", err)
	}
	if string(pubAfter) != string(pubBefore) {
		t.Fatalf("ed25519_public.pem was rewritten")
	}
}
