package hostiletest

import (
	"context"
	"fmt"
	"sync"

	"github.com/Glyndor/authcore/auth/totp"
)

// Recorder is a correct in-memory totp.StepRecorder bound to one enrollment:
// the compare and the store are one atomic step under a mutex.
type Recorder struct {
	mu   sync.Mutex
	last uint64
	// Calls counts RecordIfNewer invocations, for tests that assert the
	// module consulted the recorder at all.
	Calls int
}

// RecordIfNewer stores step when it is greater than the stored one and
// otherwise returns totp.ErrCodeReused.
func (r *Recorder) RecordIfNewer(_ context.Context, step uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls++
	if step <= r.last {
		return fmt.Errorf("step %d not newer than %d: %w", step, r.last, totp.ErrCodeReused)
	}
	r.last = step
	return nil
}
