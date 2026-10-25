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
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// ErrNoMatchingStaging is the sentinel for "KeysDir is partial but no staging
// directory matches the published file". Callers translate it into either
// "give up" (RecoverPartial) or "keep waiting" (the wait subpackage, which
// polls TryRecover).
var ErrNoMatchingStaging = errors.New("keymanager: no matching staging directory")

// FindStaging locates a .staging-* directory in KeysDir whose three
// files are regular files and whose staged private key, if the published
// private key exists, is byte-identical to it.
//
// The first match wins. Two crashing publishers would be operator confusion,
// not something to recover through.
func FindStaging(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			continue
		}
		staging := filepath.Join(dir, e.Name())

		lst, err := os.Lstat(staging)
		if err != nil || !lst.IsDir() {
			continue
		}
		// Never follow a symlink. A staged directory reached through a link
		// would defeat the recovery contract.
		if lst.Mode()&os.ModeSymlink != 0 {
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
		if !allRegular {
			continue
		}

		published, exists, err := fileio.FileBytesIfExists(filepath.Join(dir, layout.FilePrivateKey))
		if err != nil {
			return "", err
		}
		if !exists {
			return staging, nil
		}
		staged, err := fileio.ReadCapped(filepath.Join(staging, layout.FilePrivateKey))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", err
		}
		if bytes.Equal(published, staged) {
			return staging, nil
		}
	}
	return "", ErrNoMatchingStaging
}
