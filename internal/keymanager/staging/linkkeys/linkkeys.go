// Package linkkeys hard-links the three staged key files into the key
// directory in a fixed order, so that a crash at any point leaves a state
// recovery can finish or refuse.
package linkkeys

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// ErrWaitAndLoad is the sentinel Link returns when the private key link
// lost the race to another initialiser. The caller removes its own staging
// directory and waits for the winner to finish, then loads. It is unexported
// because the only legitimate caller is New itself.
var ErrWaitAndLoad = errors.New("keymanager: another initialiser won the private key link")

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

// Link hard-links the three staged files into KeysDir in the fixed order
// private, public, refresh-secret. Each successful link is durable (its inode
// was the staging inode); each failed link leaves the disk as it found it.
//
// The function returns nil on success, ErrWaitAndLoad if the private link lost
// the race to another initialiser (the caller waits and loads), or an error
// that explains what went wrong. On any error that does not preserve the
// directory's progress, the caller's staging directory has already been
// removed (unless the directory was partially published, in which case the
// staging is kept as recovery material).
func Link(dir, staging string, log layout.Logger) error {
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
