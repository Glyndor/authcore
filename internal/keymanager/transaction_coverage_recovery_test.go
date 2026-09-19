package keymanager

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Coverage tests for the recovery path: findMatchingStaging's filter
// branches, fileBytesIfExists's edge cases, completeFromStaging's
// uncommon branches, recoverPartial's inspect-error path, and
// reportLeftovers's hostile-entry path.

func TestFindMatchingStaging_skipsNonRegularStagedFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-0123456789abcdef")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(staging, filePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := findMatchingStaging(dir)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("findMatchingStaging accepted a staging dir with a non-regular file: %v", err)
	}
	if st != "" {
		t.Errorf("unexpected staging path returned: %q", st)
	}
}

func TestFindMatchingStaging_skipsSymlinkedStagingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(outside, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".staging-feedfacefeedface")); err != nil {
		t.Fatal(err)
	}
	st, err := findMatchingStaging(dir)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted a symlinked staging dir: %v %q", err, st)
	}
}

func TestFindMatchingStaging_skipsStagingWithMissingFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-0011223344556677")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := findMatchingStaging(dir)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted an incomplete staging dir: %v %q", err, st)
	}
}

func TestFindMatchingStaging_skipsHostileFileType(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-deadbeefdeadbeef")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(staging, filePublicKey), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := findMatchingStaging(dir)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted a staging dir with a directory at %s: %v %q", filePublicKey, err, st)
	}
}

func TestFileBytesIfExists_rejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, filePrivateKey)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	data, exists, err := fileBytesIfExists(path)
	if err != nil {
		t.Fatalf("fileBytesIfExists on a directory: %v", err)
	}
	if exists || data != nil {
		t.Errorf("directory at %q should be treated as missing: data=%v exists=%v", path, data, exists)
	}
}

func TestFileBytesIfExists_rejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	data, exists, err := fileBytesIfExists(filepath.Join(dir, filePrivateKey))
	if err != nil {
		t.Fatalf("fileBytesIfExists on a missing file: %v", err)
	}
	if exists || data != nil {
		t.Errorf("missing file should return (nil, false, nil): %v %v", data, exists)
	}
}

func TestRecoverPartial_rejectsSymlinkLoopInPartialSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}

	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, filePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, filePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded with a partial set containing an inspect error")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error should come from inspect, got: %v", err)
	}
}

func TestCompleteFromStaging_concurrentLinkDifferentBytesRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}

	ownerA := filepath.Join(base, "ownerA")
	stagingA := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(stagingA, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ownerA, silentLog{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := New(ownerB, silentLog{}); err != nil {
		t.Fatal(err)
	}

	copyFile(t, filepath.Join(stagingA, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(ownerB, filePublicKey), filepath.Join(dir, filePublicKey))

	err := completeFromStaging(dir, stagingA)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite a different-bytes file")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileRefreshSecret)); !os.IsNotExist(err) {
		t.Errorf("refresh secret must not be linked, stat gave: %v", err)
	}
}

func TestCompleteFromStaging_linkErrorOther(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	// Trigger the pass-two branch where linkFile returns an error that is
	// neither ErrExist nor ErrNotExist. The recovery must surface it
	// rather than swallow it.
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerDir := filepath.Join(base, "owner")
	if _, err := New(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aabbccddeeff0011")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(ownerDir, filePrivateKey), filepath.Join(dir, filePrivateKey))

	withLinkFile(t, func(_, _ string) error {
		return errors.New("EACCES simulation")
	})

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite the link error")
	}
	if !strings.Contains(err.Error(), "EACCES") {
		t.Errorf("error must include the underlying error, got: %v", err)
	}
}

func TestCompleteFromStaging_passOneReadCappedErrNotExist(t *testing.T) {
	// Trigger the pass-one ErrNotExist branch: pass 1 starts comparing,
	// but the staged file disappears between the existence check and the
	// read.
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerDir := filepath.Join(base, "owner")
	if _, err := New(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-ffeeddccbbaa9988")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))
	if err := os.Remove(filepath.Join(staging, filePublicKey)); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return errNoMatchingStaging, got: %v", err)
	}
}

func TestCompleteFromStaging_passOneReadCappedNonNotExist(t *testing.T) {
	// Trigger the pass-one readCapped error branch that is not ErrNotExist.
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerDir := filepath.Join(base, "owner")
	if _, err := New(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-9999aaaaffffdddd")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(ownerDir, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(ownerDir, filePublicKey), filepath.Join(dir, filePublicKey))
	copyFile(t, filepath.Join(ownerDir, fileRefreshSecret), filepath.Join(dir, fileRefreshSecret))
	copyFile(t, filepath.Join(ownerDir, filePrivateKey), filepath.Join(staging, filePrivateKey))
	big := make([]byte, maxKeyFileSize+1)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(staging, filePublicKey), big, 0600); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite an oversized staged file")
	}
	if !strings.Contains(err.Error(), "compare") {
		t.Errorf("error should be the pass-one compare failure, got: %v", err)
	}
}
