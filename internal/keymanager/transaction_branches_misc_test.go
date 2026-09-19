package keymanager

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These cover low-level branches: createStagingSet's CSPRNG failure,
// New's symlink preflight, and syncDir's Open failure path. Each test
// restores any package variable it changes via t.Cleanup.

// createStagingSet's "CSPRNG failed for the staging suffix" branch.
// The randRead seam is wrapped to return an error; createStagingSet must
// surface it without leaving any .staging-* entry behind.
func TestCreateStagingSetFailsCleanlyOnRandomFailure(t *testing.T) {
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	randRead = func([]byte) (int, error) {
		return 0, errors.New("csprng offline")
	}

	dir := t.TempDir()
	_, _, _, _, err := createStagingSet(dir)
	if err == nil {
		t.Fatal("createStagingSet succeeded despite randRead failing")
	}
	if !strings.Contains(err.Error(), "staging suffix") {
		t.Errorf("error must mention 'staging suffix', got: %v", err)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Errorf("staging entry %q survived a failed createStagingSet", e.Name())
		}
	}
}

// New's symlink preflight. An empty KeysDir holding a dangling symlink
// at refresh_secret.key is refused without allocating a staging directory or
// publishing the private or public keys.
func TestNewRefusesSymlinkBeforeGenerating(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "captured")
	if err := os.Symlink(target, filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded over a dangling symlink at refresh_secret.key")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention 'symlink', got: %v", err)
	}

	for _, name := range []string{filePrivateKey, filePublicKey} {
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
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Errorf("staging entry %q was allocated before the preflight ran", e.Name())
		}
	}
}

// syncDir's os.Open failure path. Calling syncDir on a path that does
// not exist must surface an fs.ErrNotExist, not classify it as ErrUnsupported.
func TestSyncDirOpenFailureIsReturned(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	err := syncDir(missing)
	if err == nil {
		t.Fatal("syncDir on a missing path returned nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("syncDir error must satisfy errors.Is(_, fs.ErrNotExist), got: %v", err)
	}
}

// New's "createStagingSet failed inside newByStaging" branch. When the
// CSPRNG is unavailable the staging directory cannot be created; New must
// surface that error and leave no .staging-* entry behind.
func TestNew_randomFailureLeavesNoStaging(t *testing.T) {
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	randRead = func([]byte) (int, error) {
		return 0, errors.New("csprng offline")
	}

	dir := t.TempDir()
	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded despite the CSPRNG being offline")
	}
	if !strings.Contains(err.Error(), "staging suffix") {
		t.Errorf("error must mention 'staging suffix', got: %v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Errorf("staging entry %q survived a failed New", e.Name())
		}
	}
}

// waitTimeoutError's "present" branch: when the wait expires on a dir that
// holds some keys but never reaches a complete set, the message must name
// what is present and what is missing.
func TestWaitTimeoutError_namesPresentAndMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wait timing depends on POSIX file semantics")
	}

	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, filePublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	prevWait, prevPoll := publishWait, publishPoll
	publishWait = 20 * time.Millisecond
	publishPoll = 2 * time.Millisecond
	t.Cleanup(func() {
		publishWait, publishPoll = prevWait, prevPoll
	})

	err := waitForSet(dir, silentLog{})
	if err == nil {
		t.Fatal("waitForSet returned nil on a partial set")
	}
	msg := err.Error()
	if !strings.Contains(msg, filePrivateKey) {
		t.Errorf("error must name %s, got: %v", filePrivateKey, err)
	}
	if !strings.Contains(msg, filePublicKey) {
		t.Errorf("error must name %s, got: %v", filePublicKey, err)
	}
}

// fileBytesIfExists's readCapped error branch: a regular file at the path
// that exceeds the size cap must surface the cap error rather than silently
// returning the bytes.
func TestFileBytesIfExists_surfacesReadCappedError(t *testing.T) {
	dir := t.TempDir()
	oversized := make([]byte, maxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	path := filepath.Join(dir, "keyfile")
	if err := os.WriteFile(path, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	data, exists, err := fileBytesIfExists(path)
	if err == nil {
		t.Fatal("fileBytesIfExists returned nil on an oversized file")
	}
	if exists || data != nil {
		t.Errorf("oversized file should not be reported as present: data=%v exists=%v", data, exists)
	}
}

// fileBytesIfExists's non-ErrNotExist os.Stat error branch: a symlink loop
// at the path returns an os.Stat error (ELOOP) that fileBytesIfExists must
// surface rather than misclassify as absent.
func TestFileBytesIfExists_surfacesStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	data, exists, err := fileBytesIfExists(loop)
	if err == nil {
		t.Fatal("fileBytesIfExists returned nil on a symlink loop")
	}
	if exists || data != nil {
		t.Errorf("symlink loop should not be reported as present: data=%v exists=%v", data, exists)
	}
}

// syncDir's permission-denied Open branch: a directory under a parent the
// process cannot search must surface an os.Stat-like error. The branch is
// reachable only when running as a non-root user; tests skip when running
// as root because root ignores directory mode bits.
func TestSyncDir_permissionDeniedOnParentIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	err := syncDir(child)
	if err == nil {
		t.Fatal("syncDir on an unsearchable parent returned nil")
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
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, fileGitignore)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	log := &recordingLog{}
	if _, err := New(dir, log); err != nil {
		t.Fatalf("a read-only key directory with no .gitignore must still load: %v", err)
	}

	var found bool
	for _, w := range log.warn {
		msg := formatEntry(w)
		if strings.Contains(msg, ".gitignore") && strings.Contains(msg, "continuing") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a Warn naming .gitignore and 'continuing', got entries: %v", log.warn)
	}
}
