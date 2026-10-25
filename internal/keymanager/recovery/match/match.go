// Package match finds the staging directory an interrupted key publish can be
// finished from.
package match

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// ErrNoMatchingStaging is the sentinel for "KeysDir is partial but no staging
// directory matches the published file". Callers translate it into either
// "give up" (RecoverPartial) or "keep waiting" (the wait subpackage, which
// polls TryRecover).
var ErrNoMatchingStaging = errors.New("keymanager: no matching staging directory")

// stagingSets lists the .staging-* directories in dir that hold all three key
// files as regular files. A symlinked staging directory is never followed: a
// staged set reached through a link would defeat the recovery contract.
func stagingSets(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var sets []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			continue
		}
		staging := filepath.Join(dir, e.Name())
		lst, err := os.Lstat(staging)
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		allRegular := true
		for _, name := range layout.KeyFileNames() {
			flst, ferr := os.Lstat(filepath.Join(staging, name))
			if ferr != nil || !flst.Mode().IsRegular() {
				allRegular = false
				break
			}
		}
		if allRegular {
			sets = append(sets, staging)
		}
	}
	return sets, nil
}

// sharesPrivateKey reports whether the staged private key is byte-identical to
// the published one. ok is false when there is no published private key or the
// staged file vanished (its owner finished and removed it).
func sharesPrivateKey(dir, staging string) (same, published bool, err error) {
	pub, exists, err := fileio.FileBytesIfExists(filepath.Join(dir, layout.FilePrivateKey))
	if err != nil || !exists {
		return false, false, err
	}
	staged, err := fileio.ReadCapped(filepath.Join(staging, layout.FilePrivateKey))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, true, nil
		}
		return false, true, err
	}
	return bytes.Equal(pub, staged), true, nil
}

// FindStaging locates a .staging-* directory in KeysDir whose three
// files are regular files, form a valid key set on their own (the public key
// belongs to the private key and the refresh secret is well formed), and whose
// staged private key, if the published private key exists, is byte-identical
// to it.
//
// The first match wins. Two crashing publishers would be operator confusion,
// not something to recover through.
func FindStaging(dir string) (string, error) {
	sets, err := stagingSets(dir)
	if err != nil {
		return "", err
	}
	for _, staging := range sets {
		same, published, err := sharesPrivateKey(dir, staging)
		if err != nil {
			return "", err
		}
		if published && !same {
			continue
		}
		// Nothing of a staged set is linked into KeysDir before the set as a
		// whole is known to be consistent.
		if keyload.Check(staging) != nil {
			continue
		}
		return staging, nil
	}
	return "", ErrNoMatchingStaging
}

// Conflict reports the first published key file whose bytes differ from the
// same file in a staging directory that holds the published private key. That
// pairing exists only when an initialisation stopped part-way and something
// else then wrote a different file into KeysDir; it is evidence of two
// initialisations, and it stays on disk until an operator resolves it, so the
// refusal does not depend on the process that noticed it. It returns "" when
// there is no conflict, and when the directory cannot be listed.
func Conflict(dir string) (string, error) {
	sets, err := stagingSets(dir)
	if err != nil {
		// A directory that cannot be listed (search without read permission)
		// is a supported deployment; there is nothing to compare against.
		return "", nil
	}
	for _, staging := range sets {
		same, published, err := sharesPrivateKey(dir, staging)
		if err != nil {
			return "", err
		}
		if !published || !same {
			continue
		}
		for _, name := range layout.KeyFileNames() {
			have, exists, err := fileio.FileBytesIfExists(filepath.Join(dir, name))
			if err != nil {
				return "", err
			}
			if !exists {
				continue
			}
			staged, err := fileio.ReadCapped(filepath.Join(staging, name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					break
				}
				return "", err
			}
			if !bytes.Equal(have, staged) {
				return name, nil
			}
		}
	}
	return "", nil
}
