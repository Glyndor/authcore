package match

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestFindMatchingStaging_skipsNonRegularStagedFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-0123456789abcdef")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(staging, layout.FilePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := FindStaging(dir)
	if !errors.Is(err, ErrNoMatchingStaging) {
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
	if err := recoverytest.SeedKeys(outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".staging-feedfacefeedface")); err != nil {
		t.Fatal(err)
	}
	st, err := FindStaging(dir)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted a symlinked staging dir: %v %q", err, st)
	}
}

func TestFindMatchingStaging_skipsStagingWithMissingFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-0011223344556677")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := FindStaging(dir)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted an incomplete staging dir: %v %q", err, st)
	}
}

func TestFindMatchingStaging_skipsHostileFileType(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-deadbeefdeadbeef")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(staging, layout.FilePublicKey), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := FindStaging(dir)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("findMatchingStaging adopted a staging dir with a directory at %s: %v %q", layout.FilePublicKey, err, st)
	}
}

// findMatchingStaging's filter branches. One staging dir is missing the
// refresh secret, one has its ed25519_public.pem as a symlink, and one is
// valid and matches the published private key. Only the valid one is
// returned; removing it makes findMatchingStaging return ErrNoMatchingStaging.
func TestFindMatchingStagingSkipsIncompleteAndSymlinkedFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}

	owner := filepath.Join(base, "owner")
	if err := recoverytest.SeedKeys(owner); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(dir, name))
	}

	incomplete := filepath.Join(dir, ".staging-99998888777766665555")
	if err := os.MkdirAll(incomplete, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(incomplete, name))
	}

	symlinked := filepath.Join(dir, ".staging-aaaa1111bbbb2222cccc")
	if err := os.MkdirAll(symlinked, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(symlinked, name))
	}
	if err := os.Symlink(filepath.Join(owner, layout.FilePublicKey), filepath.Join(symlinked, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}

	valid := filepath.Join(dir, ".staging-dddd3333eeee4444ffff")
	if err := os.MkdirAll(valid, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(valid, name))
	}

	got, err := FindStaging(dir)
	if err != nil {
		t.Fatalf("findMatchingStaging: %v", err)
	}
	if got != valid {
		t.Errorf("findMatchingStaging returned %q, want %q", got, valid)
	}

	if err := os.RemoveAll(valid); err != nil {
		t.Fatal(err)
	}
	got, err = FindStaging(dir)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("findMatchingStaging after removal: want ErrNoMatchingStaging, got %v (path %q)", err, got)
	}
	if got != "" {
		t.Errorf("findMatchingStaging returned a non-empty path %q with ErrNoMatchingStaging", got)
	}
}

// findMatchingStaging's "no published private key" branch: when no private
// key is published yet, findMatchingStaging adopts the staging directory
// without comparing bytes. This is the recovery entrypoint before any file
// has reached KeysDir.
func TestFindMatchingStaging_returnsStagingWhenNoPrivateKeyIsPublished(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if err := recoverytest.SeedKeys(owner); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-cccc2222dddd3333eeee")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}

	got, err := FindStaging(dir)
	if err != nil {
		t.Fatalf("findMatchingStaging: %v", err)
	}
	if got != staging {
		t.Errorf("findMatchingStaging returned %q, want %q", got, staging)
	}
}

// findMatchingStaging's fileBytesIfExists error branch: an oversized published
// private key must surface the cap error rather than report a false match.
func TestFindMatchingStaging_oversizedPublishedPrivateKeyIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if err := recoverytest.SeedKeys(owner); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee3333ffff4444aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	oversized := make([]byte, layout.MaxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), oversized, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := FindStaging(dir)
	if err == nil {
		t.Fatal("findMatchingStaging succeeded despite an oversized published private key")
	}
	if got != "" {
		t.Errorf("findMatchingStaging returned a non-empty path %q with an error", got)
	}
}
