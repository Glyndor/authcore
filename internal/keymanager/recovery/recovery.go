// Package recovery is the read half of the key publish transaction: it finishes
// a publish that was interrupted by completing the set from a matching staging
// directory, refuses a directory it cannot safely complete, and lets a process
// that lost the publish race wait for the winner (subpackage wait). The report
// of abandoned staging directories lives in subpackage leftovers.
package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// ErrNoMatchingStaging is the sentinel for "KeysDir is partial but no staging
// directory matches the published file". Callers translate it into either
// "give up" (RecoverPartial) or "keep waiting" (the wait subpackage, which
// polls TryRecover).
var ErrNoMatchingStaging = errors.New("keymanager: no matching staging directory")

// recoverPartialBetweenChecksHook is a test seam. It runs once, between the
// first TryRecover and the second inspectKeySet inside RecoverPartial. It lets
// a test simulate a concurrent helper that completes the set in the narrow
// window between the two inspections, which is otherwise hard to reach
// deterministically. Production callers leave it as the no-op default.
var recoverPartialBetweenChecksHook = func() {}

// TryRecover attempts to complete a partial set in KeysDir using a matching
// staging directory. It returns nil when the set is complete (the caller
// loads), ErrNoMatchingStaging when no candidate matches (the caller decides
// whether to wait or refuse), or any other error when the situation is fatal.
//
// A complete set always returns nil: a winner that has finished publishing
// removes its staging directory before the loser wakes up, and the loser must
// not then time out just because there is nothing left to recover through.
func TryRecover(dir string, log layout.Logger) error {
	state, err := fsguard.InspectKeySet(dir)
	if err != nil {
		return err
	}
	if state == fsguard.SetComplete {
		return nil
	}
	staging, err := findMatchingStaging(dir)
	if err != nil {
		return err
	}
	return completeFromStaging(dir, staging)
}

// RecoverPartial is the call from New on a partial directory: it either
// completes the set (returning nil) or refuses with safe advice. It does not
// wait: an operator-deleted partial set is refused, not silently regenerated.
//
// On a race with a winning initialiser that completes and removes its
// staging between our first inspection and our recovery attempt, the
// directory may already be complete when we would otherwise refuse. A second
// inspection closes that window so the loser loads the winner's set rather
// than failing with advice that no longer applies.
func RecoverPartial(dir string, log layout.Logger) error {
	err := TryRecover(dir, log)
	if !errors.Is(err, ErrNoMatchingStaging) {
		return err
	}
	recoverPartialBetweenChecksHook()
	state, ierr := fsguard.InspectKeySet(dir)
	if ierr != nil {
		return ierr
	}
	if state == fsguard.SetComplete {
		return nil
	}
	return refusals.Inconsistent(dir)
}

// findMatchingStaging locates a .staging-* directory in KeysDir whose three
// files are regular files and whose staged private key, if the published
// private key exists, is byte-identical to it.
//
// The first match wins. Two crashing publishers would be operator confusion,
// not something to recover through.
func findMatchingStaging(dir string) (string, error) {
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

// completeFromStaging links each missing key file from staging into KeysDir,
// after first comparing every file already present with the staged bytes.
// Any byte difference between a published file and its staged counterpart is
// the two-initialisations error: refusing before any link is attempted
// guarantees that a single mismatch leaves the directory in its original
// state, never partly-published from one initialisation and partly from
// another.
//
// The staging directory itself is left in place: its owner may still be
// running, and a later Leftover scan will report it as recoverable.
func completeFromStaging(dir, staging string) error {
	names := layout.KeyFileNames()

	// Pass one. Compare every file already present with its staged bytes.
	// Any difference refuses the whole recovery without linking anything.
	for _, name := range names {
		dst := filepath.Join(dir, name)
		existing, exists, err := fileio.FileBytesIfExists(dst)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		staged, rerr := fileio.ReadCapped(filepath.Join(staging, name))
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				// Owner finished and removed its staging mid-recovery.
				return ErrNoMatchingStaging
			}
			return fmt.Errorf("compare %s: %w", dst, rerr)
		}
		if !bytes.Equal(existing, staged) {
			return refusals.TwoInits(dir, name)
		}
	}

	// Pass two. Link each missing file from staging.
	for _, name := range names {
		dst := filepath.Join(dir, name)
		_, exists, err := fileio.FileBytesIfExists(dst)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		src := filepath.Join(staging, name)
		lerr := seams.LinkFile(src, dst)
		if lerr == nil {
			continue
		}
		if errors.Is(lerr, fs.ErrExist) {
			// Concurrent helper linked this file first. Compare bytes to
			// confirm we are recovering from the same initialisation.
			existing, rerr := fileio.ReadCapped(dst)
			if rerr != nil {
				return fmt.Errorf("compare %s after concurrent link: %w", dst, rerr)
			}
			staged, rerr := fileio.ReadCapped(src)
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					return ErrNoMatchingStaging
				}
				return fmt.Errorf("compare %s after concurrent link: %w", dst, rerr)
			}
			if !bytes.Equal(existing, staged) {
				return refusals.TwoInits(dir, name)
			}
			continue
		}
		if errors.Is(lerr, fs.ErrNotExist) {
			// The owner finished and removed its staging mid-recovery. If
			// the directory is now complete, the recovery succeeded in
			// effect; if not, keep waiting (caller decides).
			state, ierr := fsguard.InspectKeySet(dir)
			if ierr != nil {
				return ierr
			}
			if state == fsguard.SetComplete {
				return nil
			}
			return ErrNoMatchingStaging
		}
		return fmt.Errorf("link %s from staging: %w", dst, lerr)
	}

	if err := fileio.SyncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after recovery: %w", err)
	}
	return nil
}
