package keymanager_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager"
)

const metadataFile = "metadata.json"

// keyFiles are the files that hold actual key material. A migration may add,
// describe or re-read them; it may never silently replace them.
var keyFiles = []string{"ed25519_private.pem", "ed25519_public.pem", "refresh_secret.key"}

// onDiskMetadata mirrors the descriptor for assertions. The production type is
// unexported, and asserting against the JSON is the stronger check anyway: it
// pins the wire format a future version has to keep reading.
type onDiskMetadata struct {
	Format  int    `json:"format"`
	Created string `json:"created"`
	KeyID   string `json:"key_id"`
}

// snapshotKeys returns the exact bytes of every key file, so a later comparison
// proves the material survived rather than merely that loading succeeded.
func snapshotKeys(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(keyFiles))
	for _, name := range keyFiles {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test fixture path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = data
	}
	return out
}

func assertKeysUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := snapshotKeys(t, dir)
	for name, want := range before {
		if got := after[name]; string(got) != string(want) {
			t.Fatalf("%s was rewritten; key material must survive untouched", name)
		}
	}
}

func readMetadataFile(t *testing.T, dir string) onDiskMetadata {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, metadataFile)) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read %s: %v", metadataFile, err)
	}
	var m onDiskMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse %s: %v", metadataFile, err)
	}
	return m
}

// preMetadataDir builds a key directory in the layout that shipped before
// metadata.json existed: the three key files, no descriptor.
func preMetadataDir(t *testing.T) (dir string, keyID string) {
	t.Helper()
	dir = t.TempDir()
	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}
	if err := os.Remove(filepath.Join(dir, metadataFile)); err != nil {
		t.Fatalf("strip %s: %v", metadataFile, err)
	}
	return dir, km.KeyID()
}

func TestNew_writesMetadataForAFreshDirectory(t *testing.T) {
	dir := t.TempDir()
	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	m := readMetadataFile(t, dir)
	if m.Format != 1 {
		t.Errorf("format = %d, want 1", m.Format)
	}
	if m.KeyID != km.KeyID() {
		t.Errorf("key_id = %q, want %q", m.KeyID, km.KeyID())
	}
	if _, err := time.Parse(time.RFC3339, m.Created); err != nil {
		t.Errorf("created = %q, not RFC 3339: %v", m.Created, err)
	}
}

// The migration that has to exist from day one: a directory written before the
// marker existed is adopted in place. The assertion is that the key material
// survives byte for byte — an adoption that regenerated would invalidate every
// stored refresh-token and API-key hash, logging out the consumer's users.
func TestNew_adoptsPreMetadataDirectoryWithoutTouchingKeys(t *testing.T) {
	dir, keyID := preMetadataDir(t)
	before := snapshotKeys(t, dir)

	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("adopting a pre-metadata directory must succeed, got: %v", err)
	}

	assertKeysUnchanged(t, dir, before)

	if km.KeyID() != keyID {
		t.Errorf("key id changed on adoption: got %q, want %q", km.KeyID(), keyID)
	}
	m := readMetadataFile(t, dir)
	if m.Format != 1 {
		t.Errorf("adopted format = %d, want 1", m.Format)
	}
	if m.KeyID != keyID {
		t.Errorf("adopted key_id = %q, want %q", m.KeyID, keyID)
	}
}

// Adoption dates the material by the key's own mtime rather than stamping the
// moment of the upgrade, so a directory that is months old does not claim to
// have been created during the release that adopted it.
func TestNew_adoptionDatesFromTheKeyNotTheUpgrade(t *testing.T) {
	dir, _ := preMetadataDir(t)

	old := time.Now().Add(-90 * 24 * time.Hour).UTC().Truncate(time.Second)
	priv := filepath.Join(dir, "ed25519_private.pem")
	if err := os.Chtimes(priv, old, old); err != nil {
		t.Fatalf("backdate private key: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	got := readMetadataFile(t, dir).Created
	if want := old.Format(time.RFC3339); got != want {
		t.Errorf("created = %q, want the key's mtime %q", got, want)
	}
}

// A directory from a newer authcore is refused while its files are still
// untouched — the loader must not interpret material in a layout it does not
// know, and must not "recover" by regenerating.
func TestNew_refusesADirectoryFromTheFuture(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}
	before := snapshotKeys(t, dir)

	future := onDiskMetadata{Format: 99, Created: time.Now().UTC().Format(time.RFC3339), KeyID: "deadbeefdeadbeef"}
	data, err := json.Marshal(future)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, metadataFile), data, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err = keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected an error for a directory written by a newer authcore")
	}
	if !strings.Contains(err.Error(), "newer version") {
		t.Errorf("error should name the cause, got: %v", err)
	}
	assertKeysUnchanged(t, dir, before)
}

// Corrupt bookkeeping fails closed rather than being silently rewritten, and
// the error has to carry the escape: the file holds no key material, so
// deleting it is safe and re-adopts the keys.
func TestNew_refusesCorruptMetadataAndNamesTheEscape(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}
	before := snapshotKeys(t, dir)

	if err := os.WriteFile(filepath.Join(dir, metadataFile), []byte("{not json"), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected an error for unparseable metadata")
	}
	if !strings.Contains(err.Error(), "deleting it is safe") {
		t.Errorf("error should tell the operator how to recover, got: %v", err)
	}
	assertKeysUnchanged(t, dir, before)

	// And the escape has to actually work.
	if err := os.Remove(filepath.Join(dir, metadataFile)); err != nil {
		t.Fatalf("remove metadata: %v", err)
	}
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("deleting the descriptor should re-adopt the keys, got: %v", err)
	}
	assertKeysUnchanged(t, dir, before)
}

// Loading an already-marked directory must not churn the file: a rewrite on
// every start would be pointless disk traffic and would erase the original
// creation date.
func TestNew_doesNotRewriteAnUpToDateDescriptor(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}
	path := filepath.Join(dir, metadataFile)
	first, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("read %s: %v", metadataFile, err)
	}
	stamp := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("backdate %s: %v", metadataFile, err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	second, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("re-read %s: %v", metadataFile, err)
	}
	if string(first) != string(second) {
		t.Errorf("descriptor content changed on a plain reload:\nbefore %s\nafter  %s", first, second)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", metadataFile, err)
	}
	if !fi.ModTime().Equal(stamp) {
		t.Error("descriptor was rewritten on a plain reload; it should only be written when something changed")
	}
}

// Rotating the signing key by swapping the files is supported, so the
// descriptor follows the keys rather than fighting them.
func TestNew_recordsARotatedKeyID(t *testing.T) {
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	// A second, independent directory supplies a fresh pair to rotate in.
	other := t.TempDir()
	rotated, err := keymanager.New(other, testLogger{t})
	if err != nil {
		t.Fatalf("seed replacement pair: %v", err)
	}
	for _, name := range []string{"ed25519_private.pem", "ed25519_public.pem"} {
		data, err := os.ReadFile(filepath.Join(other, name)) // #nosec G304 -- test fixture path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatalf("rotate %s: %v", name, err)
		}
	}

	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("keymanager.New() after rotation: %v", err)
	}
	if km.KeyID() != rotated.KeyID() {
		t.Fatalf("loaded key id = %q, want the rotated %q", km.KeyID(), rotated.KeyID())
	}
	if got := readMetadataFile(t, dir).KeyID; got != rotated.KeyID() {
		t.Errorf("descriptor key_id = %q, want the rotated %q", got, rotated.KeyID())
	}
}

// End to end now that the directory mode survives: a KeysDir the operator has
// closed to 0500 holds its keys, cannot take the descriptor, and still starts.
// This became testable through New only once it stopped chmodding the
// directory back to 0700 (#222) — before that the mode never reached the write.
func TestNew_readOnlyDirectoryStillLoads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	dir, keyID := preMetadataDir(t)
	before := snapshotKeys(t, dir)

	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("a read-only key directory must still load, got: %v", err)
	}
	if km.KeyID() != keyID {
		t.Errorf("key id = %q, want %q", km.KeyID(), keyID)
	}
	assertKeysUnchanged(t, dir, before)

	if _, err := os.Stat(filepath.Join(dir, metadataFile)); !os.IsNotExist(err) {
		t.Errorf("the descriptor should not exist after an impossible write, stat gave: %v", err)
	}
}
