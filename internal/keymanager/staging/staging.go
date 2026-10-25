// Package staging is the write half of the key publish transaction: it
// generates a key set into a private staging directory and hard-links the
// three files into the key directory in a fixed order, so that a crash at any
// point leaves a state recovery can finish or refuse.
package staging

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

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// randRead is the source of randomness for staging directory names. It is
// exposed as a variable so a test can pin the name (the staging suffix is
// derived from CSPRNG output, and the staging path's collision behaviour is
// otherwise hard to exercise). Production callers must leave it pointing at
// rand.Read.
var randRead = rand.Read

// stagingDirName returns a fresh, randomised suffix for a staging directory.
// The dot keeps the directory hidden; 16 hex characters give 64 bits of
// collision resistance, which is enough for "no two concurrent initialisers
// pick the same name on the same KeysDir".
func stagingDirName() (string, error) {
	var b [8]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("generate staging suffix: %w", err)
	}
	return layout.StagingPrefix + hex.EncodeToString(b[:]), nil
}

// ErrWaitAndLoad is the sentinel linkKeys returns when the private key link
// lost the race to another initialiser. The caller removes its own staging
// directory and waits for the winner to finish, then loads. It is unexported
// because the only legitimate caller is New itself.
var ErrWaitAndLoad = errors.New("keymanager: another initialiser won the private key link")

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
	rsec := make([]byte, layout.RefreshSecretLen)
	if _, err := rand.Read(rsec); err != nil {
		return "", nil, nil, nil, fmt.Errorf("generate refresh secret: %w", err)
	}

	privPEM, err := pemcodec.EncodePrivateKeyPEM(edPriv)
	if err != nil {
		return "", nil, nil, nil, err
	}
	pubPEM, err := pemcodec.EncodePublicKeyPEM(edPub)
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
		{layout.FilePrivateKey, privPEM, 0600},
		{layout.FilePublicKey, pubPEM, 0644}, //nolint:gosec // public key is intentionally world-readable
		{layout.FileRefreshSecret, secretHex, 0600},
	}
	for _, f := range files {
		if err := fileio.WriteKeyFile(filepath.Join(staging, f.name), f.data, f.perm); err != nil {
			return "", nil, nil, nil, fmt.Errorf("stage %q: %w", f.name, err)
		}
	}

	if err := fileio.SyncDir(staging); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync staging directory: %w", err)
	}
	if err := fileio.SyncDir(dir); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync keys directory: %w", err)
	}

	success = true
	return staging, edPriv, edPub, rsec, nil
}

// SymlinkPreflight refuses a KeysDir whose empty-set inspection missed a
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
func SymlinkPreflight(dir string) error {
	for _, name := range layout.KeyFileNames() {
		path := filepath.Join(dir, name)
		lst, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return refusals.SymlinkTarget(path, err)
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			return refusals.SymlinkTarget(path,
				fmt.Errorf("%q is a symlink", path))
		}
	}
	return nil
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
// The function returns nil on success, ErrWaitAndLoad if the private link lost
// the race to another initialiser (the caller waits and loads), or an error
// that explains what went wrong. On any error that does not preserve the
// directory's progress, the caller's staging directory has already been
// removed (unless the directory was partially published, in which case the
// staging is kept as recovery material).
func linkKeys(dir, staging string, log layout.Logger) error {
	links := []struct {
		name  string
		point string
	}{
		{layout.FilePrivateKey, "published-private"},
		{layout.FilePublicKey, "published-public"},
		{layout.FileRefreshSecret, "published-secret"},
	}

	publishedPrivate := false
	for i, l := range links {
		src := filepath.Join(staging, l.name)
		dst := filepath.Join(dir, l.name)
		err := seams.LinkFile(src, dst)
		if err == nil {
			if i == 0 {
				publishedPrivate = true
			}
			if err := seams.Fault(l.point); err != nil {
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
			if err := seams.Fault(l.point); err != nil {
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
					return refusals.SymlinkTarget(dst, err)
				}
				// Private key already published: keep the staging directory
				// so a helper can recover through it. The operator must
				// remove the planted symlink and restart.
				return refusals.SymlinkTarget(dst, err)
			}
			if i == 0 {
				_ = os.RemoveAll(staging)
				return ErrWaitAndLoad
			}
			// Someone completed this publish for us. Compare bytes.
			existing, rerr := fileio.ReadCapped(dst)
			if rerr != nil {
				return fmt.Errorf("link %s: read existing: %w", dst, rerr)
			}
			staged, rerr := fileio.ReadCapped(src)
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					_ = os.RemoveAll(staging)
					return ErrWaitAndLoad
				}
				return fmt.Errorf("link %s: read staged: %w", dst, rerr)
			}
			if !bytes.Equal(existing, staged) {
				return refusals.TwoInits(dir, l.name)
			}
			if i == 0 {
				publishedPrivate = true
			}
			continue
		}

		if !publishedPrivate {
			_ = os.RemoveAll(staging)
			return refusals.NoHardLinks(dir, l.name, false, err)
		}
		return refusals.NoHardLinks(dir, l.name, true, err)
	}

	if err := fileio.SyncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after publish: %w", err)
	}
	if err := os.RemoveAll(staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("authcore/keymanager: could not remove staging directory %q (continuing): %v", staging, err)
	}
	if err := fileio.SyncDir(dir); err != nil {
		log.Warn("authcore/keymanager: could not sync keys directory after staging cleanup (continuing): %v", err)
	}
	return nil
}

// Publish generates a fresh key set and publishes it into dir: the staging
// directory is created and synced, then the three files are linked into place.
// It returns the generated keys so the caller does not have to parse bytes it
// just wrote.
//
// ErrWaitAndLoad means another initialiser won the race for the private key
// link; the caller waits for the winner and loads its set instead.
func Publish(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	staging, priv, pub, secret, err := createStagingSet(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := seams.Fault("staged"); err != nil {
		return nil, nil, nil, err
	}
	if err := linkKeys(dir, staging, log); err != nil {
		return nil, nil, nil, err
	}
	return priv, pub, secret, nil
}
