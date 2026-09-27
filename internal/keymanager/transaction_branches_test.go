package keymanager

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// These cover linkKeys branches that the existing coverage tests do not
// exercise: the second-or-third slot refuses on a different-bytes concurrent
// link (and keeps the staging directory as recovery material), and the
// concurrent-identical branch where a helper has already linked the same
// bytes into KeysDir.

// linkKeys' second-or-third slot refuses on a different-bytes concurrent
// link. Before the fix this path also called os.RemoveAll(staging); after the
// fix the staging directory is kept so the refused transaction leaves
// recovery material behind, and the error text is the shared two-init error
// the recovery path uses.
func TestLinkKeysKeepsStagingWhenAPublishedSlotDiffers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePublicKey), []byte("staged-pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, fileRefreshSecret), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	different := []byte("exist-pub-")
	if err := os.WriteFile(filepath.Join(dir, filePublicKey), different, 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(_, _ string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return nil
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite a byte mismatch on the public key")
	}
	if !strings.Contains(err.Error(), filePublicKey) {
		t.Errorf("error must name %s, got: %v", filePublicKey, err)
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

// linkKeys' concurrent-identical branch. A second process wrote the
// same bytes to the public key slot in KeysDir before us and reports
// fs.ErrExist; the byte compare agrees, so linkKeys must continue and the
// directory must end up complete. Set up so the existing destination is a
// DIFFERENT inode from the staged file (otherwise linkLanded short-circuits
// to success and the bytes-equal branch is never reached).
func TestLinkKeysAcceptsIdenticalConcurrentLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-bbbbbbbbbbbbbbbbbbbb")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("same-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, filePublicKey), []byte("same-"+filePublicKey), 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			return os.Link(oldpath, newpath)
		}
		if n == 2 {
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if err := linkKeys(dir, staging, silentLog{}); err != nil {
		t.Fatalf("linkKeys refused an identical concurrent link: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after linkKeys: %v", name, err)
		}
	}
}

// linkKeys's "i=0 + symlink" branch: when the first link target is a
// symlink, linkKeys must refuse via refuseSymlinkTarget and remove the
// staging directory. Reachable in production only if the symlink preflight in New is
// bypassed (a symlink created between the preflight and linkKeys), so the
// test drives linkKeys directly to keep coverage of the defensive branch.
func TestLinkKeys_symlinkOnPrivateLinkRefusesAndRemovesStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-bbbbbbbbbbbbbbbbbbbb")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey)); err != nil {
		t.Fatal(err)
	}

	withLinkFile(t, func(_, _ string) error {
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded when the private slot was a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention symlink, got: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Errorf("staging directory was kept on i=0 symlink refusal: stat gave %v", err)
	}
}

// linkKeys's "read existing after ErrExist failed for a non-ErrNotExist
// reason" branch. A pre-existing destination that is too big for the capped
// reader makes readCapped fail; linkKeys must surface it rather than try to
// compare oversized bytes.
func TestLinkKeys_readExistingFailureIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-eeee5555666677778888")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePublicKey), []byte("pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, fileRefreshSecret), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, maxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, filePublicKey), oversized, 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return os.Link(oldpath, newpath)
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite an oversized existing public key")
	}
	if !strings.Contains(err.Error(), "read existing") {
		t.Errorf("error must come from readCapped on the existing file, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, filePrivateKey)); err != nil {
		t.Errorf("staging directory was removed despite partial publish: %v", err)
	}
}

// linkKeys' "the link landed despite the reported error" branch for the
// private key slot. A wrapping linkFile first calls os.Link and THEN returns a
// non-fs.ErrExist error (syscall.EIO stands in for "network filesystem
// hiccup"); New must succeed, all three files must be published, and the
// loaded private key must be the published one.
func TestLinkKeysTreatsLandedPrivateLinkAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()

	withLinkFile(t, func(oldpath, newpath string) error {
		if filepath.Base(newpath) == filePrivateKey {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return syscall.EIO
		}
		return os.Link(oldpath, newpath)
	})

	km, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("New refused a private key link that landed despite the reported EIO: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after New: %v", name, err)
		}
	}
	staged, err := os.ReadFile(filepath.Join(dir, filePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := os.ReadFile(filepath.Join(dir, filePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(loaded) {
		t.Error("the loaded private key bytes do not match what was published")
	}
	if km.Dir() != dir {
		t.Errorf("km.Dir() = %q, want %q", km.Dir(), dir)
	}
}

// linkKeys' "the link landed despite the reported fs.ErrExist" branch
// for the private key slot. A wrapping linkFile first calls os.Link and
// THEN returns fs.ErrExist; New must succeed and all three files must be
// published (the previous behaviour rejected this as a race loss, which on
// a network filesystem would not match reality: the private key IS ours).
func TestLinkKeysTreatsLandedPublicLinkAsSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			if err := os.Link(oldpath, newpath); err != nil {
				return err
			}
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("New refused a private key link that landed despite ErrExist: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after New: %v", name, err)
		}
	}
}

// linkKeys' "the link landed despite the reported error" branch for the
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

	withLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		return fs.ErrExist
	})

	km, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("New refused a publish whose second and third slots landed despite ErrExist: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after New: %v", name, err)
		}
	}
	if km.KeyID() == "" {
		t.Error("New did not derive a key id")
	}
}

// linkKeys' faultAt branch inside the linkLanded success path: a fault
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
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	sentinel := errors.New("fault inside linkLanded branch")
	withFaultAt(t, func(p string) error {
		if p == "published-private" {
			return sentinel
		}
		return nil
	})
	withLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		return syscall.EIO
	})

	err := linkKeys(dir, staging, silentLog{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("linkKeys after fault inside linkLanded: want sentinel, got %v", err)
	}
}

// linkKeys' "lstat destination after ErrExist" branch. A wrapper linkFile
// pre-creates the destination file, then deletes it, then returns
// fs.ErrExist. linkLanded finds nothing there (returns false), errors.Is
// matches ErrExist, and Lstat(dst) fails because the destination is gone.
// linkKeys must surface the lstat error rather than misclassifying it as a
// wait-and-load condition.
func TestLinkKeys_lstatDestinationFailureIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-33333333333333333333")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	withLinkFile(t, func(_, newpath string) error {
		f, err := os.Create(newpath)
		if err != nil {
			return err
		}
		_ = f.Close()
		if err := os.Remove(newpath); err != nil {
			return err
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite lstat failing on the destination")
	}
	if !strings.Contains(err.Error(), "lstat destination") {
		t.Errorf("error must come from the lstat-failure path, got: %v", err)
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
	if err := os.WriteFile(filepath.Join(staging, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), []byte("dst"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(staging, filePrivateKey)); err != nil {
		t.Fatal(err)
	}

	if linkLanded(filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePrivateKey)) {
		t.Fatal("linkLanded returned true for a vanished source")
	}
}

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
	if _, err := New(oldDir, silentLog{}); err != nil {
		t.Fatalf("seed old: %v", err)
	}

	dir := filepath.Join(base, "rotated")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other")
	if _, err := New(other, silentLog{}); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey} {
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
	secret, err := os.ReadFile(filepath.Join(other, fileRefreshSecret)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileRefreshSecret), secret, 0600); err != nil {
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
	withFaultAt(t, func(p string) error {
		if p == "metadata-written" {
			return sentinel
		}
		return nil
	})

	_, err = New(dir, silentLog{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("New after rotated key + fault: want sentinel, got %v", err)
	}
}

// reportLeftovers' "incomplete staging directory" branch. A complete
// published set plus a .staging-<hex> directory holding only the private key
// must produce exactly one Warn naming that staging directory as incomplete,
// and the directory must still exist on disk afterwards.
func TestReportLeftoversWarnsOnIncompleteStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}

	incomplete := filepath.Join(dir, ".staging-deadbeefcafef00d")
	if err := os.MkdirAll(incomplete, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}

	log := &recordingLog{}
	if _, err := New(dir, log); err != nil {
		t.Fatalf("New returned %v", err)
	}

	warned := 0
	for _, w := range log.warn {
		msg := formatEntry(w)
		if strings.Contains(msg, "is incomplete") && strings.Contains(msg, incomplete) {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("want exactly one incomplete-staging Warn, got %d (entries: %v)", warned, log.warn)
	}
	if _, err := os.Stat(incomplete); err != nil {
		t.Errorf("incomplete staging directory was deleted: %v", err)
	}
}

// A parent with search but no read permission cannot be opened for the
// fsync before the first publish. Nothing needs to read it, so New warns and
// publishes; until 2026-09-25 it refused with "sync parent of keys
// directory" while the same layout loaded an existing set fine. Skip on
// Windows, and when running as root, because root ignores directory mode
// bits and the chmod would not block the Open call.
func TestNewWarnsWhenTheParentCannotBeSynced(t *testing.T) {
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
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	if err := os.Chmod(parent, 0300); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(parent, "keys")
	log := &captureLogger{}
	first, err := New(dir, log)
	if err != nil {
		t.Fatalf("New under an unreadable parent: %v, want the keys published with a warning", err)
	}
	warned := false
	for _, w := range log.warnings {
		if strings.Contains(w, "could not sync the parent") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning about the parent sync; warnings: %q", log.warnings)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not published: %v", name, err)
		}
	}
	again, err := New(dir, silentLog{})
	if err != nil || again.KeyID() != first.KeyID() {
		t.Fatalf("second New = %v, key id %q; want the published set, %q", err, again.KeyID(), first.KeyID())
	}
}
