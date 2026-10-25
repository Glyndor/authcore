// Package leftovers reports the .staging-* directories an interrupted key
// publish left behind in KeysDir. It only logs; it never deletes.
package leftovers

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// maxReported is how many staging directories get a warning of their own. A
// directory with hundreds of them would otherwise write hundreds of lines at
// every start; past this number one line says how many more there are, so the
// leftovers are never hidden, only summarised.
const maxReported = 8

// Report walks KeysDir once for .staging-* directories and logs a
// single Warn per directory, up to maxReported of them, then one Warn that
// counts the rest. It never deletes; it never follows a symlink; it
// is a no-op on a read-only KeysDir (ReadDir does not require write access).
//
// A staging directory whose three files equal the published ones is a copy of
// the published keys left by an interrupted initialisation. Otherwise it
// holds keys that were never published. Either way, an operator can delete it.
// A staging directory missing one of the three files is an interrupted
// initialisation that did not finish writing it; the operator can also delete
// it. The function never deletes.
func Report(dir string, log layout.Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	reported, skipped := 0, 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			continue
		}
		staging := filepath.Join(dir, e.Name())

		lst, err := os.Lstat(staging)
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if reported == maxReported {
			skipped++
			continue
		}
		reported++
		warn(dir, staging, log)
	}
	if skipped > 0 {
		log.Warn(
			"authcore/keymanager: and %d more staging directories (%d in total) were left in %q "+
				"by interrupted initialisations and can be deleted",
			skipped, skipped+reported, dir)
	}
}

// warn classifies one staging directory and logs what it holds.
func warn(dir, staging string, log layout.Logger) {
	ok := true
	stageBytes := make(map[string][]byte, 3)
	for _, name := range layout.KeyFileNames() {
		data, exists, err := fileio.FileBytesIfExists(filepath.Join(staging, name))
		if err != nil || !exists {
			ok = false
			break
		}
		stageBytes[name] = data
	}
	if !ok {
		log.Warn(
			"authcore/keymanager: staging directory %q is incomplete (left by an "+
				"initialisation that was interrupted while writing it) and can be deleted",
			staging)
		return
	}

	allMatch := true
	for _, name := range layout.KeyFileNames() {
		pub, exists, err := fileio.FileBytesIfExists(filepath.Join(dir, name))
		if err != nil || !exists || !bytes.Equal(pub, stageBytes[name]) {
			allMatch = false
			break
		}
	}

	if allMatch {
		log.Warn(
			"authcore/keymanager: staging directory %q holds a copy of the "+
				"published keys left by an interrupted initialisation and can be deleted",
			staging)
	} else {
		log.Warn(
			"authcore/keymanager: staging directory %q holds keys that were "+
				"never published and can be deleted", staging)
	}
}
