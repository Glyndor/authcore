package linkkeys

import (
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/staging/createset"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// Link' "the link landed despite the reported error" branch for the
// private key slot. A wrapping linkFile first calls os.Link and THEN returns a
// non-fs.ErrExist error (syscall.EIO stands in for "network filesystem
// hiccup"); New must succeed, all three files must be published, and the
// loaded private key must be the published one.
func TestLinkKeysTreatsLandedPrivateLinkAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()

	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		if filepath.Base(newpath) == layout.FilePrivateKey {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return syscall.EIO
		}
		return os.Link(oldpath, newpath)
	})

	priv, _, _, err := publish(dir)
	if err != nil {
		t.Fatalf("Publish refused a private key link that landed despite the reported EIO: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after Publish: %v", name, err)
		}
	}
	staged, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(loaded) {
		t.Error("the loaded private key bytes do not match what was published")
	}
	onDisk, err := pemcodec.DecodeEd25519PrivatePEM(staged, "published private key")
	if err != nil || !onDisk.Equal(priv) {
		t.Errorf("the published private key is not the one Publish returned: %v", err)
	}
}

// Link' "the link landed despite the reported fs.ErrExist" branch
// for the private key slot. A wrapping linkFile first calls os.Link and
// THEN returns fs.ErrExist; Publish must succeed and all three files must be
// published (the previous behaviour rejected this as a race loss, which on
// a network filesystem would not match reality: the private key IS ours).
func TestLinkKeysTreatsLandedPublicLinkAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()

	var fired int32
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if _, _, _, err := publish(dir); err != nil {
		t.Fatalf("Publish refused a private key link that landed despite ErrExist: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after Publish: %v", name, err)
		}
	}
}

// Link' "the link landed despite the reported error" branch for the
// second and third slots. A network filesystem can return an error after
// creating the link for any of the three slots; linkLanded must then be
// invoked for those slots too. Driving it via a wrapper that links and
// returns an error on every call exercises the i != 0 branch of the
// publishedPrivate assignment together with the faultAt / continue pair.
func TestLinkKeysTreatsLandedPublicAndSecretLinksAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()

	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		return fs.ErrExist
	})

	_, pub, _, err := publish(dir)
	if err != nil {
		t.Fatalf("Publish refused a publish whose second and third slots landed despite ErrExist: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after Publish: %v", name, err)
		}
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("Publish returned a public key of %d bytes", len(pub))
	}
}

// Link' faultAt branch inside the linkLanded success path: a fault
// injected at the moment of a successful (but reported-as-failed) link
// aborts the publish and leaves the faultAt error as the function result,
// matching the seam's contract.
func TestLinkKeysLinkLandedFaultAtReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-11111111111111111111")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	sentinel := errors.New("fault inside linkLanded branch")
	stagingtest.WithFaultAt(t, func(p string) error {
		if p == "published-private" {
			return sentinel
		}
		return nil
	})
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		return syscall.EIO
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Link after fault inside linkLanded: want sentinel, got %v", err)
	}
}

// linkLanded's "os.Stat(src) returns an error" branch. The staged source
// file is removed between linkFile and linkLanded's Stat call, simulating a
// filesystem race where the other initialiser (or an operator) cleaned up
// the staging entry just before we consulted it. linkLanded must report
// false rather than treat the missing source as a successful link.
func TestLinkLanded_returnsFalseWhenStagedSourceVanishes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("dst"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(staging, layout.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}

	if linkLanded(filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey)) {
		t.Fatal("linkLanded returned true for a vanished source")
	}
}

// publish is the publish transaction without the staging root: the same
// createset.Create then Link sequence staging.Publish runs, reachable from
// here without an import cycle.
func publish(dir string) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	staging, priv, pub, secret, err := createset.Create(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := Link(dir, staging, stagingtest.SilentLog{}); err != nil {
		return nil, nil, nil, err
	}
	return priv, pub, secret, nil
}
