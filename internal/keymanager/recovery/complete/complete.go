// Package complete finishes an interrupted key publish: it links the missing
// key files from a matching staging directory into the key directory, after
// checking that every file already published came from the same
// initialisation.
package complete

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// checkStaged judges a staged set before anything is linked. It is a variable
// so a test can reach the comparison branches that only matter when the staged
// files change between that judgement and the reads that follow it.
var checkStaged = keyload.Check

// FromStaging links each missing key file from staging into KeysDir,
// after first comparing every file already present with the staged bytes.
// Any byte difference between a published file and its staged counterpart is
// the two-initialisations error: refusing before any link is attempted
// guarantees that a single mismatch leaves the directory in its original
// state, never partly-published from one initialisation and partly from
// another.
//
// The staging directory itself is left in place: its owner may still be
// running, and a later Leftover scan will report it as recoverable.
func FromStaging(dir, staging string) error {
	names := layout.KeyFileNames()

	// Pass zero. The staged set must be consistent as a whole before a single
	// file of it is compared with, or linked next to, what is published. A
	// directory handed in by a caller that did not go through FindStaging, or
	// one rewritten since, is treated as if it had not matched.
	if err := checkStaged(staging); err != nil {
		return match.ErrNoMatchingStaging
	}

	// Pass one. Compare every file already present with its staged bytes.
	// Any difference refuses the whole recovery without linking anything.
	if err := compareWithStaged(dir, staging, names); err != nil {
		return err
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
					return match.ErrNoMatchingStaging
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
			return match.ErrNoMatchingStaging
		}
		return fmt.Errorf("link %s from staging: %w", dst, lerr)
	}

	if err := fileio.SyncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after recovery: %w", err)
	}
	return nil
}

// compareWithStaged is pass one of FromStaging: every published file must be
// byte-identical to its staged counterpart.
func compareWithStaged(dir, staging string, names []string) error {
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
				return match.ErrNoMatchingStaging
			}
			return fmt.Errorf("compare %s: %w", dst, rerr)
		}
		if !bytes.Equal(existing, staged) {
			return refusals.TwoInits(dir, name)
		}
	}
	return nil
}
