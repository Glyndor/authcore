package generate_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Staging and wait tests: an interrupted publish must leave the disk in a
// shape a fresh process can finish, and a bounded wait must time out with a
// message that names what is on disk.

func TestInterruptedInitRestarts(t *testing.T) {
	points := []string{
		"staged",
		"published-private",
		"published-public",
		"published-secret",
		"metadata-written",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			sentinel := fmt.Errorf("crash at %s", point)
			bootstraptest.WithFaultAt(t, func(p string) error {
				if p == point {
					return sentinel
				}
				return nil
			})

			_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
			if !errors.Is(err, sentinel) {
				t.Fatalf("first New at %q: want sentinel, got %v", point, err)
			}
			crashSet := bootstraptest.ReadPublishedSet(t, dir)

			bootstraptest.WithFaultAt(t, nil)
			log2 := &bootstraptest.RecordingLog{}
			if _, err := bootstraptest.New(dir, log2); err != nil {
				t.Fatalf("second New after %q: %v", point, err)
			}
			secondSet := bootstraptest.ReadSet(t, dir)

			log3 := &bootstraptest.RecordingLog{}
			if _, err := bootstraptest.New(dir, log3); err != nil {
				t.Fatalf("third New: %v", err)
			}
			thirdSet := bootstraptest.ReadSet(t, dir)

			for i := range secondSet {
				if !bytes.Equal(secondSet[i], thirdSet[i]) {
					t.Errorf("key %d changed between second and third New at %q", i, point)
				}
			}
			if point != "staged" {
				for i, b := range crashSet {
					if b == nil {
						continue
					}
					if !bytes.Equal(b, thirdSet[i]) {
						t.Errorf("key %d changed across crash+restart at %q", i, point)
					}
				}
			}

			staging := bootstraptest.ListStagingDirs(t, dir)
			if len(staging) > 1 {
				t.Errorf("at %q, expected at most one staging dir, got %v", point, staging)
			}
			if len(staging) == 1 {
				if !log2.WarnContains(staging[0]) && !log3.WarnContains(staging[0]) {
					t.Errorf("at %q, expected a Warn naming %q", point, staging[0])
				}
			}
		})
	}
}

// These cover low-level branches: createStagingSet's CSPRNG failure,
// New's symlink preflight, and syncDir's Open failure path. Each test
// restores any package variable it changes via t.Cleanup.

// New's symlink preflight. An empty KeysDir holding a dangling symlink
// at refresh_secret.key is refused without allocating a staging directory or
// publishing the private or public keys.
func TestNewRefusesSymlinkBeforeGenerating(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "captured")
	if err := os.Symlink(target, filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded over a dangling symlink at refresh_secret.key")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention 'symlink', got: %v", err)
	}

	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s was created despite the preflight refusal", name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s): unexpected error %v", name, err)
		}
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			t.Errorf("staging entry %q was allocated before the preflight ran", e.Name())
		}
	}
}

// New's "createExclusive cannot write .gitignore on a read-only directory"
// branch. The keys already exist, the descriptor is present, the directory
// is read-only for the running process, and the .gitignore has been removed
// between two starts. New must still load the keys and warn about the
// .gitignore instead of refusing to start.
func TestNew_readOnlyDirectoryCannotWriteGitignore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileGitignore)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	log := &bootstraptest.RecordingLog{}
	if _, err := bootstraptest.New(dir, log); err != nil {
		t.Fatalf("a read-only key directory with no .gitignore must still load: %v", err)
	}

	var found bool
	for _, w := range log.Entries {
		msg := bootstraptest.FormatEntry(w)
		if strings.Contains(msg, ".gitignore") && strings.Contains(msg, "continuing") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a Warn naming .gitignore and 'continuing', got entries: %v", log.Entries)
	}
}

// These cover linkKeys branches that the existing coverage tests do not
// exercise: the second-or-third slot refuses on a different-bytes concurrent
// link (and keeps the staging directory as recovery material), and the
// concurrent-identical branch where a helper has already linked the same
// bytes into KeysDir.

// The directory holds a metadata.json with one KeyID; the actual signing
// key has a different KeyID (a rotation has happened). A faultAt injected
// at "metadata-written" surfaces as a load failure rather than a warning,
// matching the seam's contract that faultAt returns are real errors.
func TestSyncMetadataFaultAtReturnsErrorOnRotatedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode semantics differ on Windows")
	}

	base := t.TempDir()
	oldDir := filepath.Join(base, "old")
	if _, err := bootstraptest.New(oldDir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed old: %v", err)
	}

	dir := filepath.Join(base, "rotated")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other")
	if _, err := bootstraptest.New(other, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
		data, err := os.ReadFile(filepath.Join(other, name)) // #nosec G304 -- test fixture
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Use the rotated owner's refresh secret so the load path matches its key
	// pair, then write the old metadata so the descriptor's KeyID is out of
	// date and the rotation code path fires.
	secret, err := os.ReadFile(filepath.Join(other, layout.FileRefreshSecret)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), secret, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(oldDir, "metadata.json")) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("fault on rotated metadata-written")
	bootstraptest.WithFaultAt(t, func(p string) error {
		if p == "metadata-written" {
			return sentinel
		}
		return nil
	})

	_, err = bootstraptest.New(dir, bootstraptest.SilentLog{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("New after rotated key + fault: want sentinel, got %v", err)
	}
}

// Concurrent initialisation tests: many goroutines on one empty directory
// must converge on a single key set, and a process that is mid-publish must
// not have its its staging directory removed by a helper that recovers
// through it.
