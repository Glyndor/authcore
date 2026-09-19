package keymanager

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Additional completeFromStaging branches reachable in production: pass-one
// readCapped ErrNotExist, pass-one oversized-file size-cap surface, pass-one
// hostile-entry surface, pass-two src-vanished after concurrent link, and
// pass-two concurrent-link oversized-file surface.

// completeFromStaging's pass-one readCapped ErrNotExist branch: pass one
// reads the staged private key after seeing the published private key
// exists; if the staged copy vanishes between those two reads, the recovery
// returns errNoMatchingStaging.
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
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-11223344aaaabbbbcccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(staging, filePublicKey), filepath.Join(dir, filePublicKey))
	if err := os.Remove(filepath.Join(staging, filePrivateKey)); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return errNoMatchingStaging, got: %v", err)
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
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aaaa2222bbbb3333cccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))
	oversized := make([]byte, maxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), oversized, 0600); err != nil {
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
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee6666ffff7777aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(staging, filePublicKey), filepath.Join(dir, filePublicKey))
	if err := os.Remove(filepath.Join(dir, filePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, filePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite a hostile public key entry")
	}
	if !strings.Contains(err.Error(), filePublicKey) {
		t.Errorf("error must name %s, got: %v", filePublicKey, err)
	}
}

// completeFromStaging's pass-two concurrent-link src-vanished branch: the
// link succeeds, but the staged source is gone by the time the recovery
// reads it for the byte compare.
func TestCompleteFromStaging_concurrentLinkSrcVanished(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee0000ffff1111aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))

	withLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		_ = os.RemoveAll(staging)
		return fs.ErrExist
	})

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return errNoMatchingStaging, got: %v", err)
	}
}

// completeFromStaging's pass-two concurrent-link dst-read error branch: a
// helper writes an oversized file at the public key destination before
// reporting fs.ErrExist.
func TestCompleteFromStaging_concurrentLinkOversizedFileIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aaaa7777bbbb8888cccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))

	var fired int32
	withLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			oversized := make([]byte, maxKeyFileSize+1)
			for i := range oversized {
				oversized[i] = 'A'
			}
			if err := os.WriteFile(newpath, oversized, 0644); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(filepath.Join(staging, fileRefreshSecret), filepath.Join(dir, fileRefreshSecret))
	})

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite an oversized concurrent-link public key")
	}
	if !strings.Contains(err.Error(), "concurrent link") {
		t.Errorf("error must come from the concurrent-link readCapped, got: %v", err)
	}
}
