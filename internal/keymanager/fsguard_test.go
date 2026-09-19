package keymanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type silentLog struct{}

func (silentLog) Info(string, ...any)  {}
func (silentLog) Warn(string, ...any)  {}
func (silentLog) Error(string, ...any) {}
func (silentLog) Debug(string, ...any) {}

// TestNewRefusesADanglingSymlink is the regression for the defect this file
// exists for. A dangling link at a managed filename used to be classified as
// absent by os.Stat, so every presence check agreed the directory was empty
// and the freshly generated private key was written at the link target,
// outside KeysDir entirely.
func TestNewRefusesADanglingSymlink(t *testing.T) {
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "keys")
			outside := filepath.Join(base, "outside")
			mustMkdir(t, dir, 0700)
			mustMkdir(t, outside, 0755)

			target := filepath.Join(outside, "captured")
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}

			_, err := New(dir, silentLog{})
			if err == nil {
				t.Fatal("New succeeded through a dangling symlink")
			}
			// The message is part of the fix. An operator who reaches this
			// must not be told to delete all key files, which is the advice
			// that destroys every auth/field column.
			if !strings.Contains(err.Error(), "symlink") {
				t.Errorf("the error does not mention the symlink: %v", err)
			}
			if strings.Contains(err.Error(), "delete all key files") {
				t.Errorf("the error gives the destructive advice: %v", err)
			}
			if _, statErr := os.Lstat(target); statErr == nil {
				t.Errorf("something was written outside KeysDir at %s", target)
			}
		})
	}
}

// TestNewRefusesANonRegularFile covers the other way a planted entry reaches
// the write path.
func TestNewRefusesANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, filePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded with a directory where the private key belongs")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestCreateExclusiveRefusesAnExistingFile covers the narrower race the old
// code lost: a regular file appearing between the presence check and the
// write kept its own permissions, so a world-readable file planted at that
// moment received the private key.
func TestCreateExclusiveRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, filePrivateKey)
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(path, []byte("secret"), 0600); err == nil {
		t.Fatal("createExclusive overwrote an existing file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("the existing file was written to anyway: %q", data)
	}
}

// TestSymlinkedKeysStillLoad is the counterweight, and it is the reason reads
// were left following links.
//
// docs/key-management.md tells the operator to mount a Kubernetes Secret at
// KeysDir, and Kubernetes projects a Secret volume as a tree of symlinks. A
// loader that refused links would pass a security review and break every
// replica following the deployment guide, so this test pins the case: an
// existing key set reached through symlinks loads, and loads the same keys.
func TestSymlinkedKeysStillLoad(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	mounted := filepath.Join(base, "mounted")
	mustMkdir(t, real, 0700)
	mustMkdir(t, mounted, 0700)

	original, err := New(real, silentLog{})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret, fileMetadata} {
		if err := os.Symlink(filepath.Join(real, name), filepath.Join(mounted, name)); err != nil {
			t.Fatal(err)
		}
	}

	viaLinks, err := New(mounted, silentLog{})
	if err != nil {
		t.Fatalf("a Kubernetes-style symlinked key set failed to load: %v", err)
	}
	if viaLinks.KeyID() != original.KeyID() {
		t.Errorf("loaded a different key through the links: %s vs %s", viaLinks.KeyID(), original.KeyID())
	}
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestNewRefusesASymlinkLoop covers the entry Stat cannot classify at all. A
// link that points at itself is neither absent nor a regular file, and the
// loader has to stop on it rather than read it as an empty slot and generate
// a key pair beside it.
func TestNewRefusesASymlinkLoop(t *testing.T) {
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			loop := filepath.Join(dir, name)
			if err := os.Symlink(loop, loop); err != nil {
				t.Fatal(err)
			}

			_, err := New(dir, silentLog{})
			if err == nil {
				t.Fatal("New succeeded over a symlink loop")
			}
			if !strings.Contains(err.Error(), "inspecting") {
				t.Errorf("the refusal did not come from the classification: %v", err)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, e := range entries {
				switch e.Name() {
				case filePrivateKey, filePublicKey, fileRefreshSecret:
					if e.Name() != name {
						t.Errorf("key material %s was generated beside the loop", e.Name())
					}
				}
			}
		})
	}
}
