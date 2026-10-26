package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A start that finds a half-published set finishes it and hands back the keys
// that are on disk: it must neither fail nor return empty material.
func TestOpen_RecoversAPartialSetAndReturnsItsKeys(t *testing.T) {
	bootstraptest.PosixOnly(t)
	dir := filepath.Join(t.TempDir(), "keys")
	crash := errors.New("simulated crash")
	done := false
	bootstraptest.WithFault(t, func(point string) error {
		if point == "published-private" && !done {
			done = true
			return crash
		}
		return nil
	})
	var log bootstraptest.Recorder

	if _, _, _, err := bootstrap.Open(dir, &log); !errors.Is(err, crash) {
		t.Fatalf("first Open = %v, want the simulated crash", err)
	}
	priv, pub, secret, err := bootstrap.Open(dir, &log)
	if err != nil {
		t.Fatalf("second Open = %v, want recovery", err)
	}

	if len(priv) == 0 || len(pub) == 0 || len(secret) != layout.RefreshSecretLen {
		t.Fatalf("recovery returned empty material: %d/%d/%d bytes", len(priv), len(pub), len(secret))
	}
	for _, name := range layout.KeyFileNames() {
		if len(bootstraptest.ReadFile(t, dir, name)) == 0 {
			t.Errorf("%s is empty or missing after recovery", name)
		}
	}
}

// A dangling link at a key name on an empty directory is refused before a
// single key is generated or published.
func TestOpen_DanglingLinkAtAKeyNameIsRefusedBeforeAnythingIsPublished(t *testing.T) {
	bootstraptest.PosixOnly(t)
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	var log bootstraptest.Recorder

	if _, _, _, err := bootstrap.Open(dir, &log); err == nil {
		t.Fatal("Open accepted a dangling link at a key name")
	}
	if _, err := os.Lstat(filepath.Join(dir, layout.FilePrivateKey)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a private key was published before the link was noticed: %v", err)
	}
}

// A KeysDir that is a link is refused before anything is created, tightened
// or written: the chmod and the .gitignore would otherwise land on whatever
// the link points at.
func TestOpen_SymlinkedDirectoryIsRefusedBeforeAnythingIsTouched(t *testing.T) {
	bootstraptest.PosixOnly(t)
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "keys")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var log bootstraptest.Recorder

	if _, _, _, err := bootstrap.Open(link, &log); err == nil {
		t.Fatal("Open accepted a symbolic link as the key directory")
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("the link's target was chmodded to %04o", got)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Errorf("the link's target holds %v (%v), want it untouched", entries, err)
	}
}
