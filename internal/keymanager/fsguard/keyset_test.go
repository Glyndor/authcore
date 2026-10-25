package fsguard

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInspect_classifiesAbsentPresentAndHostile(t *testing.T) {
	dir := t.TempDir()

	if st, err := Inspect(dir, layout.FilePrivateKey); st != FileAbsent || err != nil {
		t.Fatalf("missing file: got %v, %v; want FileAbsent, nil", st, err)
	}

	touch(t, dir, layout.FilePrivateKey)
	if st, err := Inspect(dir, layout.FilePrivateKey); st != FilePresent || err != nil {
		t.Fatalf("regular file: got %v, %v; want FilePresent, nil", st, err)
	}

	if err := os.Mkdir(filepath.Join(dir, layout.FilePublicKey), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := Inspect(dir, layout.FilePublicKey)
	if st != FileHostile || err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: got %v, %v; want FileHostile and a not-a-regular-file error", st, err)
	}
}

// Reads follow links (a Kubernetes Secret is a tree of them), so a link to a
// regular file is present; a dangling one resolves to nothing and is absent,
// which the write side refuses separately.
func TestInspect_followsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, layout.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}
	if st, err := Inspect(dir, layout.FilePrivateKey); st != FilePresent || err != nil {
		t.Fatalf("link to a regular file: got %v, %v; want FilePresent, nil", st, err)
	}

	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	if st, err := Inspect(dir, layout.FilePublicKey); st != FileAbsent || err != nil {
		t.Fatalf("dangling link: got %v, %v; want FileAbsent, nil", st, err)
	}

	loop := filepath.Join(dir, layout.FileRefreshSecret)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if st, err := Inspect(dir, layout.FileRefreshSecret); st != FileHostile || err == nil {
		t.Fatalf("link loop: got %v, %v; want FileHostile and an error", st, err)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	if Exists(dir, layout.FilePrivateKey) {
		t.Fatal("Exists reported a missing file")
	}
	touch(t, dir, layout.FilePrivateKey)
	if !Exists(dir, layout.FilePrivateKey) {
		t.Fatal("Exists missed a present file")
	}
	// A classification error counts as present so the message names the entry.
	if err := os.Mkdir(filepath.Join(dir, layout.FilePublicKey), 0700); err != nil {
		t.Fatal(err)
	}
	if !Exists(dir, layout.FilePublicKey) {
		t.Fatal("Exists must report a hostile entry as present")
	}
}

func TestInspectKeySet_countsTheManagedFiles(t *testing.T) {
	dir := t.TempDir()
	if st, err := InspectKeySet(dir); st != SetEmpty || err != nil {
		t.Fatalf("empty dir: got %v, %v; want SetEmpty, nil", st, err)
	}

	touch(t, dir, layout.FilePrivateKey)
	if st, err := InspectKeySet(dir); st != SetPartial || err != nil {
		t.Fatalf("one file: got %v, %v; want SetPartial, nil", st, err)
	}

	touch(t, dir, layout.FilePublicKey)
	touch(t, dir, layout.FileRefreshSecret)
	if st, err := InspectKeySet(dir); st != SetComplete || err != nil {
		t.Fatalf("three files: got %v, %v; want SetComplete, nil", st, err)
	}
}

func TestInspectKeySet_surfacesAClassificationError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.FileRefreshSecret), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectKeySet(dir); err == nil {
		t.Fatal("a directory at a managed name must be an error, not a missing file")
	}
}

func TestPresentAndMissing(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, layout.FilePublicKey)
	present, missing := PresentAndMissing(dir)
	if !slices.Equal(present, []string{layout.FilePublicKey}) {
		t.Errorf("present = %v", present)
	}
	if !slices.Equal(missing, []string{layout.FilePrivateKey, layout.FileRefreshSecret}) {
		t.Errorf("missing = %v", missing)
	}
}

func TestCreateExclusive_writesANewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), layout.FileGitignore)
	if err := CreateExclusive(path, []byte("*\n"), 0600); err != nil {
		t.Fatalf("CreateExclusive: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil || string(got) != "*\n" {
		t.Fatalf("read back %q, %v", got, err)
	}
}

func TestCreateExclusive_refusesToWriteThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	err := CreateExclusive(path, []byte("secret"), 0600)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("CreateExclusive through a dangling link = %v, want a refusal naming symlinks", err)
	}
	if _, serr := os.Stat(outside); !os.IsNotExist(serr) {
		t.Fatalf("the key was written at the link target: %v", serr)
	}
}

func TestCreateExclusive_otherOpenErrorsPassThrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", layout.FilePrivateKey)
	err := CreateExclusive(path, []byte("x"), 0600)
	if err == nil || strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("a missing parent is not a pre-existing entry; got %v", err)
	}
}
