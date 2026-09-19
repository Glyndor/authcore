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

// These cover completeFromStaging branches: pass-two concurrent-identical
// link and pass-two concurrent-different link.

// T3a: completeFromStaging's pass-two concurrent-identical branch. A second
// helper linked the missing public key with bytes identical to the staged
// bytes, so recovery continues instead of refusing.
func TestCompleteFromStagingAcceptsIdenticalConcurrentLink(t *testing.T) {
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

	staging := filepath.Join(dir, ".staging-cccccc112233445566")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if err := completeFromStaging(dir, staging); err != nil {
		t.Fatalf("completeFromStaging refused an identical concurrent link: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
}

// T3b: completeFromStaging's pass-two concurrent-different branch. A second
// helper linked the missing public key with bytes that differ from the staged
// bytes, so the recovery refuses with the shared two-init error.
func TestCompleteFromStagingRefusesDifferentConcurrentLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerA := filepath.Join(base, "ownerA")
	if _, err := New(ownerA, silentLog{}); err != nil {
		t.Fatal(err)
	}
	ownerB := filepath.Join(base, "ownerB")
	if _, err := New(ownerB, silentLog{}); err != nil {
		t.Fatal(err)
	}

	staging := filepath.Join(dir, ".staging-ddddddddeeeeffff0000")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))

	foreignPub, err := os.ReadFile(filepath.Join(ownerB, filePublicKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			if err := os.WriteFile(newpath, foreignPub, 0644); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return nil
	})

	err = completeFromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging accepted a different concurrent link")
	}
	if !strings.Contains(err.Error(), filePublicKey) {
		t.Errorf("error must name %s, got: %v", filePublicKey, err)
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
}

// T4a: completeFromStaging's "source vanished while set completes" branch.
// linkFile returns fs.ErrNotExist (the owner finished and removed its
// staging), the directory is now complete, so the recovery returns nil.
func TestCompleteFromStagingSourceVanishesWhileSetCompletes(t *testing.T) {
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
	staging := filepath.Join(dir, ".staging-11112222333344445555")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(staging, filePublicKey), filepath.Join(dir, filePublicKey))

	var fired int32
	withLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			missing := filepath.Join(dir, fileRefreshSecret)
			src := filepath.Join(staging, fileRefreshSecret)
			if err := os.Link(src, missing); err != nil {
				return err
			}
			_ = os.RemoveAll(staging)
			return fs.ErrNotExist
		}
		return nil
	})

	if err := completeFromStaging(dir, staging); err != nil {
		t.Fatalf("completeFromStaging refused a complete set whose source vanished: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
}

// T4b: completeFromStaging's "source vanished, set still partial" branch.
// linkFile returns fs.ErrNotExist, the directory is not yet complete, so the
// recovery returns errNoMatchingStaging.
func TestCompleteFromStagingSourceVanishesAndSetIsStillPartial(t *testing.T) {
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
	staging := filepath.Join(dir, ".staging-eeee5555666677778888")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	copyFile(t, filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey))

	withLinkFile(t, func(_, _ string) error {
		return fs.ErrNotExist
	})

	err := completeFromStaging(dir, staging)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return errNoMatchingStaging, got: %v", err)
	}
}
