package complete

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

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
	if err := recoverytest.SeedKeys(ownerDir); err != nil {
		t.Fatal(err)
	}

	staging := filepath.Join(dir, ".staging-cccccc112233445566")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	recoverytest.CopyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	var fired int32
	recoverytest.WithLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if err := FromStaging(dir, staging); err != nil {
		t.Fatalf("completeFromStaging refused an identical concurrent link: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
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
	if err := recoverytest.SeedKeys(ownerA); err != nil {
		t.Fatal(err)
	}
	ownerB := filepath.Join(base, "ownerB")
	if err := recoverytest.SeedKeys(ownerB); err != nil {
		t.Fatal(err)
	}

	staging := filepath.Join(dir, ".staging-ddddddddeeeeffff0000")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(ownerA, name), filepath.Join(staging, name))
	}
	recoverytest.CopyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	foreignPub, err := os.ReadFile(filepath.Join(ownerB, layout.FilePublicKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}

	var fired int32
	recoverytest.WithLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			if err := os.WriteFile(newpath, foreignPub, 0644); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return nil
	})

	err = FromStaging(dir, staging)
	if err == nil {
		t.Fatal("completeFromStaging accepted a different concurrent link")
	}
	if !strings.Contains(err.Error(), layout.FilePublicKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePublicKey, err)
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
	if err := recoverytest.SeedKeys(ownerDir); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-11112222333344445555")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	recoverytest.CopyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	recoverytest.CopyFile(t, filepath.Join(staging, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))

	var fired int32
	recoverytest.WithLinkFile(t, func(_, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			missing := filepath.Join(dir, layout.FileRefreshSecret)
			src := filepath.Join(staging, layout.FileRefreshSecret)
			if err := os.Link(src, missing); err != nil {
				return err
			}
			_ = os.RemoveAll(staging)
			return fs.ErrNotExist
		}
		return nil
	})

	if err := FromStaging(dir, staging); err != nil {
		t.Fatalf("completeFromStaging refused a complete set whose source vanished: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
}

// T4b: completeFromStaging's "source vanished, set still partial" branch.
// linkFile returns fs.ErrNotExist, the directory is not yet complete, so the
// recovery returns match.ErrNoMatchingStaging.
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
	if err := recoverytest.SeedKeys(ownerDir); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee5555666677778888")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
	}
	recoverytest.CopyFile(t, filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	recoverytest.WithLinkFile(t, func(_, _ string) error {
		return fs.ErrNotExist
	})

	err := FromStaging(dir, staging)
	if !errors.Is(err, match.ErrNoMatchingStaging) {
		t.Fatalf("completeFromStaging should return match.ErrNoMatchingStaging, got: %v", err)
	}
}
