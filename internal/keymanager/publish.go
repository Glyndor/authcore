package keymanager

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// waitForSet polls KeysDir until all three key files are present, running
// the recovery step once per poll so a publisher that died mid-way does not
// leave its peers waiting forever. The wait is bounded by publishWait.
//
// It returns nil when the set is complete (caller loads); an error if the
// wait expires or if recovery surfaces a real inconsistency.
func waitForSet(dir string, log logger) error {
	deadline := time.Now().Add(publishWait)
	for {
		err := tryRecover(dir, log)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errNoMatchingStaging) {
			return err
		}
		if time.Now().After(deadline) {
			return waitTimeoutError(dir)
		}
		time.Sleep(publishPoll)
	}
}

// waitTimeoutError builds the message the spec calls for: another initialiser
// started publishing and did not finish within the wait, names what is on
// disk, and points at a restart. It never mentions symlinks.
func waitTimeoutError(dir string) error {
	present, missing := presentAndMissing(dir)
	presentStr := "none"
	if len(present) > 0 {
		presentStr = strings.Join(present, ", ")
	}
	missingStr := "none"
	if len(missing) > 0 {
		missingStr = strings.Join(missing, ", ")
	}
	return fmt.Errorf(
		"another initialiser started publishing keys in %q and did not finish "+
			"within the wait: present {%s}, missing {%s}; "+
			"a restart finishes it when the staging directory is still there",
		dir, presentStr, missingStr)
}

// presentAndMissing lists the three key filenames by presence in dir, for
// error messages. A classification error (symlink loop, hostile entry) counts
// as present, so the message names the entry the operator has to look at.
func presentAndMissing(dir string) (present, missing []string) {
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if exists(dir, name) {
			present = append(present, name)
		} else {
			missing = append(missing, name)
		}
	}
	return present, missing
}
