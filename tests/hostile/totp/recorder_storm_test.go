package totp_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// trailRecorder is memRecorder that also remembers, in commit order, every
// step it accepted. The order is the order of the lock, which is the order in
// which an application's compare-and-swap would commit.
type trailRecorder struct {
	mu       sync.Mutex
	last     uint64
	accepted []uint64
}

func (r *trailRecorder) RecordIfNewer(_ context.Context, step uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if step <= r.last {
		return totp.ErrCodeReused
	}
	r.last = step
	r.accepted = append(r.accepted, step)
	return nil
}

// Many requests, each with a code from a different step of the window, race
// through Verify against one recorder. Whatever the interleaving: the steps
// that were accepted form a strictly increasing sequence (no step twice, none
// walked backwards), the recorder ends on the highest accepted step, and every
// request that was refused was refused as a reuse, not as an unrelated error.
// Run under -race this is also a data-race check on the module.
func TestHostile_TOTP_recorderUnderAMixedStepStorm(t *testing.T) {
	m := newModule(t, totp.Config{SkewSteps: totp.Int(2)})
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		rec := &trailRecorder{}
		const goroutines = 96
		var (
			wg      sync.WaitGroup
			start   = make(chan struct{})
			mu      sync.Mutex
			bad     []string
			success = map[uint64]int{}
		)
		for i := 0; i < goroutines; i++ {
			offset := int64(i%5) - 2 // steps current-2 .. current+2
			code := codeAt(t, secret, uint64(int64(step)+offset))
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := m.Verify(context.Background(), secret, code, rec)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					success[uint64(int64(step)+offset)]++
				case !errors.Is(err, totp.ErrCodeReused):
					bad = append(bad, err.Error())
				}
			}()
		}
		close(start)
		wg.Wait()

		if len(bad) > 0 {
			return fmt.Sprintf("unexpected errors: %v", bad)
		}
		for i := 1; i < len(rec.accepted); i++ {
			if rec.accepted[i] <= rec.accepted[i-1] {
				return fmt.Sprintf("accepted steps went %v: not strictly increasing", rec.accepted)
			}
		}
		for s, n := range success {
			if n != 1 {
				return fmt.Sprintf("step %d accepted %d times", s, n)
			}
		}
		if len(rec.accepted) == 0 || rec.accepted[len(rec.accepted)-1] != rec.last {
			return fmt.Sprintf("recorder ends at %d but accepted %v", rec.last, rec.accepted)
		}
		if len(success) != len(rec.accepted) {
			return fmt.Sprintf("%d steps reported accepted, recorder holds %d", len(success), len(rec.accepted))
		}
		return ""
	})
}

// Verify and VerifyStep share one module across goroutines with different
// secrets: a code is only ever valid for the secret it was made for, so no
// request can be accepted on another account's code, even in a crowd.
func TestHostile_TOTP_accountsDoNotBleedIntoEachOtherUnderConcurrency(t *testing.T) {
	m := newModule(t)
	const accounts = 24
	secrets := make([]string, accounts)
	for i := range secrets {
		secrets[i] = sharedSecret(t)
	}
	atStableStep(t, func(step uint64) string {
		var (
			wg  sync.WaitGroup
			mu  sync.Mutex
			bad []string
		)
		for i := 0; i < accounts; i++ {
			for j := 0; j < accounts; j++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := m.VerifyStep(secrets[j], codeAt(t, secrets[i], step), 0)
					mu.Lock()
					defer mu.Unlock()
					if (i == j) != (err == nil) || (i != j && !errors.Is(err, totp.ErrInvalidCode)) {
						bad = append(bad, fmt.Sprintf("code of account %d against account %d: %v, want ErrInvalidCode across accounts", i, j, err))
					}
				}()
			}
		}
		wg.Wait()
		if len(bad) > 0 {
			return fmt.Sprintf("%d crossings, first: %s", len(bad), bad[0])
		}
		return ""
	})
}
