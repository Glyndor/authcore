// Package preflight refuses a key directory that hides a symlink at one of the
// three managed filenames before the publish transaction creates anything.
package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// Symlinks refuses a KeysDir whose empty-set inspection missed a
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
func Symlinks(dir string) error {
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
