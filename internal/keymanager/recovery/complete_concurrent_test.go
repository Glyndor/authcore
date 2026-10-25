package recovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

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
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee0000ffff1111aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	withLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		_ = os.RemoveAll(staging)
		return fs.ErrExist
	})

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, ErrNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return ErrNoMatchingStaging, got: %v", err)
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
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aaaa7777bbbb8888cccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	var fired int32
	withLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			oversized := make([]byte, layout.MaxKeyFileSize+1)
			for i := range oversized {
				oversized[i] = 'A'
			}
			if err := os.WriteFile(newpath, oversized, 0644); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(filepath.Join(staging, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))
	})

	err := completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite an oversized concurrent-link public key")
	}
	if !strings.Contains(err.Error(), "concurrent link") {
		t.Errorf("error must come from the concurrent-link readCapped, got: %v", err)
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
	if _, err := seedKeys(ownerA, silentLog{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := seedKeys(ownerB, silentLog{}); err != nil {
		t.Fatal(err)
	}

	copyFile(t, filepath.Join(stagingA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	copyFile(t, filepath.Join(ownerB, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))

	err := completeFromStaging(dir, stagingA)
	if err == nil {
		t.Fatal("completeFromStaging succeeded despite a different-bytes file")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FileRefreshSecret)); !os.IsNotExist(err) {
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
	if _, err := seedKeys(ownerDir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-aabbccddeeff0011")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(ownerDir, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

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
