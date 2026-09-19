package keymanager

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Coverage tests for the low-level file/directory operations the publish
// transaction uses: writeKeyFile, writeMetadata, syncDir, createStagingSet.

func TestWriteKeyFile_rejectsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, filePrivateKey)
	if err := os.WriteFile(path, []byte("already there"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(path, []byte("fresh"), 0600); err == nil {
		t.Fatal("writeKeyFile overwrote an existing file")
	}
	if got, _ := os.ReadFile(path); string(got) != "already there" {
		t.Errorf("existing file was clobbered: %q", got)
	}
}

func TestWriteKeyFile_rejectsDirectoryAtTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, filePrivateKey)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	err := writeKeyFile(path, []byte("data"), 0600)
	if err == nil {
		t.Fatal("writeKeyFile succeeded with a directory at the target path")
	}
}

func TestWriteMetadata_renameFailsWhenDestinationIsADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, fileMetadata), 0700); err != nil {
		t.Fatal(err)
	}
	m := metadata{Format: currentFormat, Created: "2026-09-19T00:00:00Z", KeyID: "0123456789abcdef"}
	err := writeMetadata(dir, m)
	if err == nil {
		t.Fatal("writeMetadata succeeded with a directory at the destination")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("expected the rename failure to surface, got: %v", err)
	}
}

func TestWriteMetadata_openFailsOnReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	m := metadata{Format: currentFormat, Created: "2026-09-19T00:00:00Z", KeyID: "0123456789abcdef"}
	err := writeMetadata(dir, m)
	if err == nil {
		t.Fatal("writeMetadata succeeded on a read-only directory")
	}
}

func TestSyncDir_classifiesOpenError(t *testing.T) {
	// Calling syncDir on a path that does not exist returns an error
	// that is not ErrUnsupported or EINVAL; the helper propagates it.
	err := syncDir(filepath.Join(t.TempDir(), "no-such-dir"))
	if err == nil {
		t.Fatal("syncDir on a missing path returned nil")
	}
	if strings.Contains(err.Error(), "unsupported") {
		t.Errorf("missing-path error was misclassified as unsupported: %v", err)
	}
}

func TestCreateStagingSet_mkdirFailsWhenNameIsTaken(t *testing.T) {
	// Wrap randRead so the staging name is deterministic, then plant a
	// directory at that name to force Mkdir to fail.
	dir := t.TempDir()
	planted := filepath.Join(dir, ".staging-0001020304050607")
	if err := os.Mkdir(planted, 0700); err != nil {
		t.Fatal(err)
	}
	origRead := randRead
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	}
	t.Cleanup(func() { randRead = origRead })

	_, _, _, _, err := createStagingSet(dir)
	if err == nil {
		t.Fatalf("createStagingSet succeeded; expected collision with %s", planted)
	}
	if !strings.Contains(err.Error(), "staging directory") {
		t.Errorf("error must mention the staging directory, got: %v", err)
	}
}

func TestReportLeftovers_readOnlyKeysDirIsHandled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory read permissions")
	}

	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	log := silentLog{}
	reportLeftovers(dir, log) // must not panic, must not return an error path
}

func TestReportLeftovers_handlesHostileEntry(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaa"), []byte("not a dir"), 0600); err != nil {
		t.Fatal(err)
	}
	reportLeftovers(dir, silentLog{}) // must not panic
}
