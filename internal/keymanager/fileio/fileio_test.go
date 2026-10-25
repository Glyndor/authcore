package fileio

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

const streamRefusal = "exceeds 4096-byte cap"

func endlessStream(t *testing.T) string {
	t.Helper()
	const path = "/dev/zero"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available on %s: the read-time cap is not exercised here", path, runtime.GOOS)
	}
	return path
}

func TestReadCapped_refusesAStreamLongerThanTheCap(t *testing.T) {
	_, err := ReadCapped(endlessStream(t))
	if err == nil || !strings.Contains(err.Error(), streamRefusal) {
		t.Fatalf("ReadCapped(/dev/zero) = %v, want the read-time refusal %q", err, streamRefusal)
	}
	// The Stat check words its refusal with the size it saw; this one must
	// not have been it, or the read-time check is still untested.
	if strings.Contains(err.Error(), "bytes, exceeds") {
		t.Fatalf("refused by the Stat check, not the read-time check: %v", err)
	}
}

// The pair on each side of the cap, from regular files: exactly the cap is
// read whole, one byte more is refused by the Stat check.
func TestReadCapped_regularFilesAtAndPastTheCap(t *testing.T) {
	dir := t.TempDir()

	atCap := filepath.Join(dir, "at-cap")
	if err := os.WriteFile(atCap, bytes.Repeat([]byte{'a'}, layout.MaxKeyFileSize), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadCapped(atCap)
	if err != nil || len(data) != layout.MaxKeyFileSize {
		t.Fatalf("readCapped at the cap: %d bytes, %v; want %d, nil", len(data), err, layout.MaxKeyFileSize)
	}

	pastCap := filepath.Join(dir, "past-cap")
	if err := os.WriteFile(pastCap, bytes.Repeat([]byte{'a'}, layout.MaxKeyFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCapped(pastCap); err == nil || !strings.Contains(err.Error(), "is 4097 bytes, exceeds 4096-byte cap") {
		t.Fatalf("readCapped one past the cap = %v, want the Stat refusal", err)
	}
}

func TestWriteKeyFile_rejectsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.WriteFile(path, []byte("already there"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, []byte("fresh"), 0600); err == nil {
		t.Fatal("writeKeyFile overwrote an existing file")
	}
	if got, _ := os.ReadFile(path); string(got) != "already there" {
		t.Errorf("existing file was clobbered: %q", got)
	}
}

func TestWriteKeyFile_rejectsDirectoryAtTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	err := WriteKeyFile(path, []byte("data"), 0600)
	if err == nil {
		t.Fatal("writeKeyFile succeeded with a directory at the target path")
	}
}

func TestSyncDir_classifiesOpenError(t *testing.T) {
	// Calling syncDir on a path that does not exist returns an error
	// that is not ErrUnsupported or EINVAL; the helper propagates it.
	err := SyncDir(filepath.Join(t.TempDir(), "no-such-dir"))
	if err == nil {
		t.Fatal("syncDir on a missing path returned nil")
	}
	if strings.Contains(err.Error(), "unsupported") {
		t.Errorf("missing-path error was misclassified as unsupported: %v", err)
	}
}

// syncDir's os.Open failure path. Calling syncDir on a path that does
// not exist must surface an fs.ErrNotExist, not classify it as ErrUnsupported.
func TestSyncDirOpenFailureIsReturned(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	err := SyncDir(missing)
	if err == nil {
		t.Fatal("syncDir on a missing path returned nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("syncDir error must satisfy errors.Is(_, fs.ErrNotExist), got: %v", err)
	}
}

// syncDir's permission-denied Open branch: a directory under a parent the
// process cannot search must surface an os.Stat-like error. The branch is
// reachable only when running as a non-root user; tests skip when running
// as root because root ignores directory mode bits.
func TestSyncDir_permissionDeniedOnParentIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	err := SyncDir(child)
	if err == nil {
		t.Fatal("syncDir on an unsearchable parent returned nil")
	}
}

// fileBytesIfExists's readCapped error branch: a regular file at the path
// that exceeds the size cap must surface the cap error rather than silently
// returning the bytes.
func TestFileBytesIfExists_surfacesReadCappedError(t *testing.T) {
	dir := t.TempDir()
	oversized := make([]byte, layout.MaxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	path := filepath.Join(dir, "keyfile")
	if err := os.WriteFile(path, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	data, exists, err := FileBytesIfExists(path)
	if err == nil {
		t.Fatal("fileBytesIfExists returned nil on an oversized file")
	}
	if exists || data != nil {
		t.Errorf("oversized file should not be reported as present: data=%v exists=%v", data, exists)
	}
}

// fileBytesIfExists's non-ErrNotExist os.Stat error branch: a symlink loop
// at the path returns an os.Stat error (ELOOP) that fileBytesIfExists must
// surface rather than misclassify as absent.
func TestFileBytesIfExists_surfacesStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	data, exists, err := FileBytesIfExists(loop)
	if err == nil {
		t.Fatal("fileBytesIfExists returned nil on a symlink loop")
	}
	if exists || data != nil {
		t.Errorf("symlink loop should not be reported as present: data=%v exists=%v", data, exists)
	}
}

func TestFileBytesIfExists_rejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	data, exists, err := FileBytesIfExists(path)
	if err != nil {
		t.Fatalf("fileBytesIfExists on a directory: %v", err)
	}
	if exists || data != nil {
		t.Errorf("directory at %q should be treated as missing: data=%v exists=%v", path, data, exists)
	}
}

func TestFileBytesIfExists_rejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	data, exists, err := FileBytesIfExists(filepath.Join(dir, layout.FilePrivateKey))
	if err != nil {
		t.Fatalf("fileBytesIfExists on a missing file: %v", err)
	}
	if exists || data != nil {
		t.Errorf("missing file should return (nil, false, nil): %v %v", data, exists)
	}
}
