package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// completeFromStaging's pass-one readCapped ErrNotExist branch: pass one
// reads the staged private key after seeing the published private key
// exists; if the staged copy vanishes between those two reads, the recovery
// returns ErrNoMatchingStaging.
func TestCompleteFromStaging_passOneStagedFileVanishes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-11223344aaaabbbbcccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	copyFile(t, filepath.Join(staging, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))
	if err := os.Remove(filepath.Join(staging, layout.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return ErrNoMatchingStaging, got: %v", err)
	}
}

// completeFromStaging's pass-one fileBytesIfExists error branch via a
// previously-sized file replaced with an oversized one.
func TestCompleteFromStaging_passOneOversizedFileIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aaaa2222bbbb3333cccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	oversized := make([]byte, layout.MaxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), oversized, 0600); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite an oversized existing file")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error must come from the size cap, got: %v", err)
	}
}

// completeFromStaging's pass-one fileBytesIfExists error branch via a
// hostile entry: a symlink loop at the published public key returns an
// os.Stat error other than ErrNotExist.
func TestCompleteFromStaging_passOneHostileEntryIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee6666ffff7777aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	copyFile(t, filepath.Join(staging, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, layout.FilePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite a hostile public key entry")
	}
	if !strings.Contains(err.Error(), layout.FilePublicKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePublicKey, err)
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
	if _, err := seedKeys(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-ffeeddccbbaa9988")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	if err := os.Remove(filepath.Join(staging, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return ErrNoMatchingStaging, got: %v", err)
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
	if _, err := seedKeys(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-9999aaaaffffdddd")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(ownerDir, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	copyFile(t, filepath.Join(ownerDir, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))
	copyFile(t, filepath.Join(ownerDir, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))
	copyFile(t, filepath.Join(ownerDir, layout.FilePrivateKey), filepath.Join(staging, layout.FilePrivateKey))
	big := make([]byte, layout.MaxKeyFileSize+1)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey), big, 0600); err != nil {
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
