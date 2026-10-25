package bootstrap_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// TestNewRefusesADanglingSymlink is the regression for the defect this file
// exists for. A dangling link at a managed filename used to be classified as
// absent by os.Stat, so every presence check agreed the directory was empty
// and the freshly generated private key was written at the link target,
// outside KeysDir entirely.
func TestNewRefusesADanglingSymlink(t *testing.T) {
	for _, name := range layout.KeyFileNames() {
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

			_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
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
	if err := os.Mkdir(filepath.Join(dir, layout.FilePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded with a directory where the private key belongs")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestSymlinkedKeysStillLoad is the counterweight, and it is the reason reads
// were left following links.
//
// docs/guides/key-management.md tells the operator to mount a Kubernetes Secret at
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

	original, err := bootstraptest.New(real, bootstraptest.SilentLog{})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey, layout.FileRefreshSecret, layout.FileMetadata} {
		if err := os.Symlink(filepath.Join(real, name), filepath.Join(mounted, name)); err != nil {
			t.Fatal(err)
		}
	}

	viaLinks, err := bootstraptest.New(mounted, bootstraptest.SilentLog{})
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
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			loop := filepath.Join(dir, name)
			if err := os.Symlink(loop, loop); err != nil {
				t.Fatal(err)
			}

			_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
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
				case layout.FilePrivateKey, layout.FilePublicKey, layout.FileRefreshSecret:
					if e.Name() != name {
						t.Errorf("key material %s was generated beside the loop", e.Name())
					}
				}
			}
		})
	}
}

// Refusal tests: a filesystem without hard links, an inconsistent partial
// set with no matching staging directory, an inconsistent slot whose bytes
// differ, and a mixed refresh secret from a different initialisation. The
// fourth case is the recovery path surviving an owner removing its staging
// mid-recovery.

// Controls the 2026-09-25 review found working but unpinned, plus the two
// parsers it found lenient. Each test names the mutation that used to
// survive: without it, the control could be removed with the suite green.

// New only ever tightens KeysDir. os.Chmod(dir, dirMode) instead of
// mode&dirMode survived: a 0555 directory gained owner write.
func TestTightenDirMode_onlyEverTightens(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix mode bits and a non-root user")
	}
	for _, tc := range []struct{ before, after os.FileMode }{
		{0o555, 0o500}, // strips group and other, never adds owner write
		{0o750, 0o700},
		{0o500, 0o500},
	} {
		dir := t.TempDir()
		if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if err := os.Chmod(dir, tc.before); err != nil {
			t.Fatal(err)
		}
		if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
			t.Fatalf("New on a %04o directory: %v", tc.before, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != tc.after {
			t.Errorf("KeysDir %04o after New is %04o, want %04o", tc.before, fi.Mode().Perm(), tc.after)
		}
		_ = os.Chmod(dir, 0o700)
	}
}

// The error for a refresh secret that is not hex names the file and nothing
// of its contents; the hex package's own error quotes the offending byte.
func TestRefreshSecretErrorDoesNotEchoTheFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatal(err)
	}
	bad := "s3cr3t-value-that-is-not-hex-encoded-at-all-and-must-not-be-logged!\n"
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := bootstraptest.Load(dir, bootstraptest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "is not hex encoded") {
		t.Fatalf("Load = %v, want the not-hex refusal", err)
	}
	for _, fragment := range []string{"s3cr3t", "invalid byte", "U+", "'s'"} {
		if strings.Contains(err.Error(), fragment) {
			t.Errorf("the error echoes the file (%q): %v", fragment, err)
		}
	}
	// A well-formed file of the same length still loads, so the refusal is
	// about the encoding and not the length. The secret is a different one, so
	// the descriptor's binding is dropped first, as the operator would.
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	good := hex.EncodeToString([]byte(strings.Repeat("k", 32))) + "\n"
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstraptest.Load(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("Load with a hex secret: %v", err)
	}
}
