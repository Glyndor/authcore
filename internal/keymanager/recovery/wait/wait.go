// Package wait lets a process that lost the key publish race wait for the
// winner to finish populating KeysDir, finishing a publish the winner left
// half done.
package wait

import (
	"errors"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// publishWait bounds how long a process that lost the publish race waits for a
// winner to finish populating KeysDir. Exposed so tests can shorten it.
var publishWait = 5 * time.Second

// publishPoll is the interval between checks during that wait. Exposed so tests
// can shorten it.
var publishPoll = 10 * time.Millisecond

// ForSet polls KeysDir until all three key files are present, running
// the recovery step once per poll so a publisher that died mid-way does not
// leave its peers waiting forever. The wait is bounded by publishWait.
//
// It returns nil when the set is complete (caller loads); an error if the
// wait expires or if recovery surfaces a real inconsistency.
func ForSet(dir string, log layout.Logger) error {
	deadline := time.Now().Add(publishWait)
	for {
		err := recovery.TryRecover(dir, log)
		if err == nil {
			return nil
		}
		if !errors.Is(err, recovery.ErrNoMatchingStaging) {
			return err
		}
		if time.Now().After(deadline) {
			return refusals.WaitTimeout(dir)
		}
		time.Sleep(publishPoll)
	}
}
