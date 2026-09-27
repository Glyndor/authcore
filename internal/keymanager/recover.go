package keymanager

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// errNoMatchingStaging is the sentinel for "KeysDir is partial but no staging
// directory matches the published file". It is internal: callers translate it
// into either "give up" (recoverPartial) or "keep waiting" (tryRecover).
var errNoMatchingStaging = errors.New("keymanager: no matching staging directory")

// recoverPartialBetweenChecksHook is a test seam. It runs once, between the
// first tryRecover and the second inspectKeySet inside recoverPartial. It lets
// a test simulate a concurrent helper that completes the set in the narrow
// window between the two inspections, which is otherwise hard to reach
// deterministically. Production callers leave it as the no-op default.
var recoverPartialBetweenChecksHook = func() {}

// tryRecover attempts to complete a partial set in KeysDir using a matching
// staging directory. It returns nil when the set is complete (the caller
// loads), errNoMatchingStaging when no candidate matches (the caller decides
// whether to wait or refuse), or any other error when the situation is fatal.
//
// A complete set always returns nil: a winner that has finished publishing
// removes its staging directory before the loser wakes up, and the loser must
// not then time out just because there is nothing left to recover through.
func tryRecover(dir string, log logger) error {
	state, err := inspectKeySet(dir)
	if err != nil {
		return err
	}
	if state == setComplete {
		return nil
	}
	staging, err := findMatchingStaging(dir)
	if err != nil {
		return err
	}
	return completeFromStaging(dir, staging)
}

// recoverPartial is the call from New on a partial directory: it either
// completes the set (returning nil) or refuses with safe advice. It does not
// wait: an operator-deleted partial set is refused, not silently regenerated.
//
// On a race with a winning initialiser that completes and removes its
// staging between our first inspection and our recovery attempt, the
// directory may already be complete when we would otherwise refuse. A second
// inspection closes that window so the loser loads the winner's set rather
// than failing with advice that no longer applies.
func recoverPartial(dir string, log logger) error {
	err := tryRecover(dir, log)
	if !errors.Is(err, errNoMatchingStaging) {
		return err
	}
	recoverPartialBetweenChecksHook()
	state, ierr := inspectKeySet(dir)
	if ierr != nil {
		return ierr
	}
	if state == setComplete {
		return nil
	}
	return refuseInconsistent(dir)
}

// refuseInconsistent is the message returned when a partial set has no
// matching staging directory. It must NOT contain the phrase "delete all key
// files", which since auth/field shipped is the advice that destroys every
// encrypted column.
func refuseInconsistent(dir string) error {
	present, missing := presentAndMissing(dir)
	return fmt.Errorf(
		"key directory %q is in an inconsistent state: present {%s}, missing {%s}; "+
			"restore the missing file(s) from a backup; refresh_secret.key must "+
			"not be deleted or regenerated because every stored refresh-token "+
			"hash, API-key hash and every auth/field encrypted column depends on it",
		dir, strings.Join(present, ", "), strings.Join(missing, ", "))
}

// refuseRegeneration is the message returned when metadata.json records a key
// set and none of its files remain. Like refuseInconsistent it must not advise
// deleting key files; deleting metadata.json is named as the deliberate way to
// start over, since that is the only file whose loss costs nothing.
func refuseRegeneration(dir string, meta *metadata) error {
	return fmt.Errorf(
		"key directory %q held a key set (metadata.json records key id %q) and none of its files remain; "+
			"restore them from a backup. Generating a new set would invalidate every issued token, "+
			"every stored refresh-token and API-key hash and every auth/field encrypted column; "+
			"to start over with new keys on purpose, delete metadata.json",
		dir, meta.KeyID)
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
		if !strings.HasPrefix(e.Name(), stagingPrefix) {
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
		for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
			flst, ferr := os.Lstat(filepath.Join(staging, name))
			if ferr != nil || !flst.Mode().IsRegular() {
				allRegular = false
				break
			}
		}
		if !allRegular {
			continue
		}

		published, exists, err := fileBytesIfExists(filepath.Join(dir, filePrivateKey))
		if err != nil {
			return "", err
		}
		if !exists {
			return staging, nil
		}
		staged, err := readCapped(filepath.Join(staging, filePrivateKey))
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
	return "", errNoMatchingStaging
}

// fileBytesIfExists returns the bytes of path when it exists and is a regular
// file. A symlink resolves to its target, so a regular-file target returns its
// bytes; a non-regular target returns ("", false, nil) so the caller skips it.
func fileBytesIfExists(path string) ([]byte, bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, nil
	}
	data, err := readCapped(path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
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
	names := []string{filePrivateKey, filePublicKey, fileRefreshSecret}

	// Pass one. Compare every file already present with its staged bytes.
	// Any difference refuses the whole recovery without linking anything.
	for _, name := range names {
		dst := filepath.Join(dir, name)
		existing, exists, err := fileBytesIfExists(dst)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		staged, rerr := readCapped(filepath.Join(staging, name))
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				// Owner finished and removed its staging mid-recovery.
				return errNoMatchingStaging
			}
			return fmt.Errorf("compare %s: %w", dst, rerr)
		}
		if !bytes.Equal(existing, staged) {
			return twoInitsError(dir, name)
		}
	}

	// Pass two. Link each missing file from staging.
	for _, name := range names {
		dst := filepath.Join(dir, name)
		_, exists, err := fileBytesIfExists(dst)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		src := filepath.Join(staging, name)
		lerr := linkFile(src, dst)
		if lerr == nil {
			continue
		}
		if errors.Is(lerr, fs.ErrExist) {
			// Concurrent helper linked this file first. Compare bytes to
			// confirm we are recovering from the same initialisation.
			existing, rerr := readCapped(dst)
			if rerr != nil {
				return fmt.Errorf("compare %s after concurrent link: %w", dst, rerr)
			}
			staged, rerr := readCapped(src)
			if rerr != nil {
				if errors.Is(rerr, fs.ErrNotExist) {
					return errNoMatchingStaging
				}
				return fmt.Errorf("compare %s after concurrent link: %w", dst, rerr)
			}
			if !bytes.Equal(existing, staged) {
				return twoInitsError(dir, name)
			}
			continue
		}
		if errors.Is(lerr, fs.ErrNotExist) {
			// The owner finished and removed its staging mid-recovery. If
			// the directory is now complete, the recovery succeeded in
			// effect; if not, keep waiting (caller decides).
			state, ierr := inspectKeySet(dir)
			if ierr != nil {
				return ierr
			}
			if state == setComplete {
				return nil
			}
			return errNoMatchingStaging
		}
		return fmt.Errorf("link %s from staging: %w", dst, lerr)
	}

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after recovery: %w", err)
	}
	return nil
}

// twoInitsError reports that the directory holds material from two different
// initialisations and refuses to write or delete anything.
func twoInitsError(dir, name string) error {
	return fmt.Errorf(
		"key directory %q holds %s from two different initialisations; "+
			"the published bytes do not match the staged bytes; "+
			"refusing to write or delete any further files in this directory",
		dir, name)
}

// reportLeftovers walks KeysDir once for .staging-* directories and logs a
// single Warn per directory. It never deletes; it never follows a symlink; it
// is a no-op on a read-only KeysDir (ReadDir does not require write access).
//
// A staging directory whose three files equal the published ones is a copy of
// the published keys left by an interrupted initialisation. Otherwise it
// holds keys that were never published. Either way, an operator can delete it.
// A staging directory missing one of the three files is an interrupted
// initialisation that did not finish writing it; the operator can also delete
// it. The function never deletes.
func reportLeftovers(dir string, log logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), stagingPrefix) {
			continue
		}
		staging := filepath.Join(dir, e.Name())

		lst, err := os.Lstat(staging)
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}

		ok := true
		stageBytes := make(map[string][]byte, 3)
		for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
			data, exists, err := fileBytesIfExists(filepath.Join(staging, name))
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
			continue
		}

		allMatch := true
		for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
			pub, exists, err := fileBytesIfExists(filepath.Join(dir, name))
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
}
