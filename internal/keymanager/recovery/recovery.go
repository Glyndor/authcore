// Package recovery is the read half of the key publish transaction: it finishes
// a publish that was interrupted by completing the set from a matching staging
// directory, refuses a directory it cannot safely complete, and lets a process
// that lost the publish race wait for the winner (subpackage wait). Finding the
// staging directory to finish from lives in subpackage match, linking it into
// place in subpackage complete, and the report of abandoned staging
// directories in subpackage leftovers.
package recovery

import (
	"errors"

	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/complete"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// ErrNoMatchingStaging is the sentinel for "KeysDir is partial but no staging
// directory matches the published file". Callers translate it into either
// "give up" (RecoverPartial) or "keep waiting" (the wait subpackage, which
// polls TryRecover).
var ErrNoMatchingStaging = match.ErrNoMatchingStaging

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
	staging, err := match.FindStaging(dir)
	if err != nil {
		return err
	}
	return complete.FromStaging(dir, staging)
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
