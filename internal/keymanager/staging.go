package keymanager

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// linkFile is the os.Link call, exposed as a variable so a test can simulate a
// filesystem that does not support hard links. Production callers must leave it
// pointing at os.Link; nothing else is portable.
var linkFile = os.Link

// randRead is the source of randomness for staging directory names. It is
// exposed as a variable so a test can pin the name (the staging suffix is
// derived from CSPRNG output, and the staging path's collision behaviour is
// otherwise hard to exercise). Production callers must leave it pointing at
// rand.Read.
var randRead = rand.Read

// publishWait bounds how long a process that lost the publish race waits for a
// winner to finish populating KeysDir. Exposed so tests can shorten it.
var publishWait = 5 * time.Second

// publishPoll is the interval between checks during that wait. Exposed so tests
// can shorten it.
var publishPoll = 10 * time.Millisecond

// faultAt is a test seam. When a test sets it to return a non-nil error at one
// of the named points, the publish transaction aborts at that point WITHOUT
// cleaning up, leaving the disk in the state a process crash would leave it in.
//
// Valid points:
//
//	"staged"             staging directory created and synced, no link attempted yet
//	"published-private"  ed25519_private.pem hard-linked into KeysDir
//	"published-public"   ed25519_public.pem hard-linked into KeysDir
//	"published-secret"   refresh_secret.key hard-linked into KeysDir
//	"metadata-before-rename"  metadata temp file written, not yet renamed.
//	                       Only reachable by calling writeMetadata directly;
//	                       through New, syncMetadata treats a metadata write
//	                       failure as a warning by design.
//	"metadata-written"   metadata.json atomically replaced
//
// Production callers must leave it returning nil at every point.
var faultAt = func(point string) error { return nil }

// stagingPrefix names the staging directory entries. The dot hides them from a
// casual listing; the prefix makes them findable for recovery and the leftover
// scan.
const stagingPrefix = ".staging-"

// syncDir flushes a directory's metadata to disk.
//
// On Windows, fs.Sync on a directory handle does not flush directory metadata
// and can return an access error, so there is nothing useful to do. Return
// nil immediately rather than translating a Windows-specific error.
//
// On filesystems that do not implement directory sync (some FUSE mounts, some
// network filesystems) the kernel returns errors.ErrUnsupported or
// syscall.EINVAL on the Sync call; both are reported as nil because the
// alternative is to refuse to start on a filesystem the operator chose.
// Failing to open the directory is a real error and is returned verbatim.
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	// #nosec G304 -- path is KeysDir or a staging directory inside it; both come from the trusted config and a fixed layout
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.EINVAL) {
			return nil
		}
		return err
	}
	return nil
}

// stagingDirName returns a fresh, randomised suffix for a staging directory.
// The dot keeps the directory hidden; 16 hex characters give 64 bits of
// collision resistance, which is enough for "no two concurrent initialisers
// pick the same name on the same KeysDir".
func stagingDirName() (string, error) {
	var b [8]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("generate staging suffix: %w", err)
	}
	return stagingPrefix + hex.EncodeToString(b[:]), nil
}

// errWaitAndLoad is the sentinel linkKeys returns when the private key link
// lost the race to another initialiser. The caller removes its own staging
// directory and waits for the winner to finish, then loads. It is unexported
// because the only legitimate caller is New itself.
var errWaitAndLoad = errors.New("keymanager: another initialiser won the private key link")

// createStagingSet allocates a private staging directory inside KeysDir and
// writes the three key files into it with their final names and modes.
//
// The directory is created with os.Mkdir (not MkdirAll) at mode 0700; a name
// collision is an error rather than something to overwrite. A failure at any
// point removes the staging directory before returning so the caller never
// leaves a half-populated staging behind. On success the caller publishes the
// three files by hard-linking them into KeysDir.
func createStagingSet(dir string) (string, ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	suffix, err := stagingDirName()
	if err != nil {
		return "", nil, nil, nil, err
	}
	staging := filepath.Join(dir, suffix)
	if err := os.Mkdir(staging, 0700); err != nil {
		return "", nil, nil, nil, fmt.Errorf("create staging directory %q: %w", staging, err)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(staging)
		}
	}()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("generate Ed25519 key pair: %w", err)
	}
	rsec := make([]byte, refreshSecretLen)
	if _, err := rand.Read(rsec); err != nil {
		return "", nil, nil, nil, fmt.Errorf("generate refresh secret: %w", err)
	}

	privPEM, err := encodePrivateKeyPEM(edPriv)
	if err != nil {
		return "", nil, nil, nil, err
	}
	pubPEM, err := encodePublicKeyPEM(edPub)
	if err != nil {
		return "", nil, nil, nil, err
	}
	// Hex-encode so the file survives editors that mangle binary content.
	// Keep the trailing newline the existing writer produces.
	secretHex := append([]byte(hex.EncodeToString(rsec)), '\n')

	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{filePrivateKey, privPEM, 0600},
		{filePublicKey, pubPEM, 0644}, //nolint:gosec // public key is intentionally world-readable
		{fileRefreshSecret, secretHex, 0600},
	}
	for _, f := range files {
		if err := writeKeyFile(filepath.Join(staging, f.name), f.data, f.perm); err != nil {
			return "", nil, nil, nil, fmt.Errorf("stage %q: %w", f.name, err)
		}
	}

	if err := syncDir(staging); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync staging directory: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync keys directory: %w", err)
	}

	success = true
	return staging, edPriv, edPub, rsec, nil
}

// refuseSymlinkTarget returns the same refusal createExclusive returns today
// when the destination is a symlink. The text is the contract: an operator
// who reaches this must not be told to delete all key files, which since
// auth/field shipped is the advice that destroys every encrypted column.
func refuseSymlinkTarget(dst string, linkErr error) error {
	return fmt.Errorf(
		"refusing to write %q: something already exists there. If it is a "+
			"symlink, authcore never writes key material through one: remove it "+
			"and let authcore create the file, or point KeysDir at the real "+
			"directory: %w", dst, linkErr)
}

// symlinkPreflight refuses a KeysDir whose empty-set inspection missed a
// dangling symlink at one of the three managed filenames. inspectKeySet uses
// os.Stat, which classifies a dangling link as absent; without this check the
// publish transaction would generate a fresh key pair, create a staging
// directory, and only notice the symlink when the refresh-secret link failed.
// That leaves the private and public keys published but the directory partial,
// and a partial KeysDir is what authcore commits to never create on its own.
//
// The check is only run on the empty-set path: a directory that already has
// files on disk was classified by Stat and the load path takes over. An Lstat
// that returns ErrNotExist on a filename means the slot is genuinely empty;
// anything else is treated as a symlink and refused.
func symlinkPreflight(dir string) error {
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		path := filepath.Join(dir, name)
		lst, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return refuseSymlinkTarget(path, err)
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			return refuseSymlinkTarget(path,
				fmt.Errorf("%q is a symlink", path))
		}
	}
	return nil
}

// refuseNoHardLinks reports a filesystem that cannot give the hard-link
// guarantee authcore needs to publish keys safely. If the caller had already
// published the private key, the staging directory is preserved so a helper
// can recover through it; otherwise it is removed.
func refuseNoHardLinks(dir, name string, keepStaging bool, linkErr error) error {
	keep := ""
	if keepStaging {
		keep = "; the staging directory has been kept as recovery material"
	}
	return fmt.Errorf(
		"filesystem under %q does not support hard links, which authcore "+
			"needs to create keys safely (%s): %w%s; create the keys once on a "+
			"local filesystem and mount them, or supply them through Config.KeyStore",
		dir, name, linkErr, keep)
}

// linkLanded reports whether dst is the same file as src after a linkFile
// call returned an error. A network filesystem can report an error after the
// link has been created on disk; the link did happen, the kernel just did not
// acknowledge it. os.SameFile compares device and inode, both of which a
// successful hard link equalises to src's.
//
// The check uses Lstat on dst, not Stat. A pre-existing symlink at dst that
// happens to point at src would look identical through Stat (the resolved
// inode matches), but the publish transaction must refuse to write through a
// symlink regardless of whether the symlink's target already happens to be
// the staged file; Lstat returns the link's own inode and SameFile then
// correctly reports false. The call is best-effort: when either Stat fails
// (e.g. the link truly did not land), linkLanded returns false and the
// caller treats the link as failed.
func linkLanded(src, dst string) bool {
	s1, err := os.Stat(src)
	if err != nil {
		return false
	}
	s2, err := os.Lstat(dst)
	if err != nil {
		return false
	}
	return os.SameFile(s1, s2)
}

// linkKeys hard-links the three staged files into KeysDir in the fixed order
// private, public, refresh-secret. Each successful link is durable (its inode
// was the staging inode); each failed link leaves the disk as it found it.
//
// The function returns nil on success, errWaitAndLoad if the private link lost
// the race to another initialiser (the caller waits and loads), or an error
// that explains what went wrong. On any error that does not preserve the
// directory's progress, the caller's staging directory has already been
// removed (unless the directory was partially published, in which case the
// staging is kept as recovery material).
func linkKeys(dir, staging string, log logger) error {
	links := []struct {
		name  string
		point string
	}{
		{filePrivateKey, "published-private"},
		{filePublicKey, "published-public"},
		{fileRefreshSecret, "published-secret"},
	}

	publishedPrivate := false
	for i, l := range links {
		src := filepath.Join(staging, l.name)
		dst := filepath.Join(dir, l.name)
		err := linkFile(src, dst)
		if err == nil {
			if i == 0 {
				publishedPrivate = true
			}
			if err := faultAt(l.point); err != nil {
				return err
			}
			continue
		}

		// A network filesystem can report an error from linkFile after the
		// link has actually been created; check whether dst is now the same
		// file as src before treating the call as a failure.
		if linkLanded(src, dst) {
			if i == 0 {
				publishedPrivate = true
			}
			if err := faultAt(l.point); err != nil {
				return err
			}
			continue
		}

		if errors.Is(err, fs.ErrExist) {
			lst, lstErr := os.Lstat(dst)
			if lstErr != nil {
				return fmt.Errorf("link %s: lstat destination: %w", dst, lstErr)
			}
			if lst.Mode()&os.ModeSymlink != 0 {
				if i == 0 {
					_ = os.RemoveAll(staging)
					return refuseSymlinkTarget(dst, err)
				}
				// Private key already published: keep the staging directory
				// so a helper can recover through it. The operator must
				// remove the planted symlink and restart.
				return refuseSymlinkTarget(dst, err)
			}
			if i == 0 {
				_ = os.RemoveAll(staging)
				return errWaitAndLoad
			}
			// Someone completed this publish for us. Compare bytes.
			existing, rerr := readCapped(dst)
			if rerr != nil {
				return fmt.Errorf("link %s: read existing: %w", dst, rerr)
			}
			staged, rerr := readCapped(src)
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					_ = os.RemoveAll(staging)
					return errWaitAndLoad
				}
				return fmt.Errorf("link %s: read staged: %w", dst, rerr)
			}
			if !bytes.Equal(existing, staged) {
				return twoInitsError(dir, l.name)
			}
			if i == 0 {
				publishedPrivate = true
			}
			continue
		}

		if !publishedPrivate {
			_ = os.RemoveAll(staging)
			return refuseNoHardLinks(dir, l.name, false, err)
		}
		return refuseNoHardLinks(dir, l.name, true, err)
	}

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after publish: %w", err)
	}
	if err := os.RemoveAll(staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("authcore/keymanager: could not remove staging directory %q (continuing): %v", staging, err)
	}
	if err := syncDir(dir); err != nil {
		log.Warn("authcore/keymanager: could not sync keys directory after staging cleanup (continuing): %v", err)
	}
	return nil
}
