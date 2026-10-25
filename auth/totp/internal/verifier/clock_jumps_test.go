package verifier_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

func atUnix(m *TOTP, sec int64, nsec int64) { m.clock = clock.Fixed(time.Unix(sec, nsec).UTC()) }

func mustSecret(t *testing.T) (string, []byte) {
	t.Helper()
	s := rfcSecretB32
	key, err := decodeSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	return s, key
}

// A code of step S is accepted by exactly the clock readings from the start of
// step S-skew up to, but not including, the start of step S+skew+1, probed at
// the nanosecond on each side of both edges and in the middle of the range.
func TestVerifyStep_windowEdgesAreExactToTheNanosecond(t *testing.T) {
	secret, key := mustSecret(t)
	const step = 1_000_000 // far from both ends of the range
	for _, skew := range []int{0, 1, 3, 10} {
		m := newTOTP(t, Config{SkewSteps: Int(skew)})
		code := generateTOTP(key, step)
		first := int64(step-skew) * timeStep // first second that still accepts
		past := int64(step+skew+1) * timeStep
		for _, tc := range []struct {
			sec, nsec int64
			want      bool
		}{
			{first - 1, 999_999_999, false},
			{first, 0, true},
			{first + (past-first)/2, 0, true},
			{past - 1, 999_999_999, true},
			{past, 0, false},
			{past, 1, false},
		} {
			atUnix(m, tc.sec, tc.nsec)
			got, err := m.VerifyStep(secret, code, 0)
			switch {
			case tc.want && (err != nil || got != step):
				t.Errorf("skew %d at %d.%09d: = %d, %v; want step %d", skew, tc.sec, tc.nsec, got, err, uint64(step))
			case !tc.want && !errors.Is(err, ErrInvalidCode):
				t.Errorf("skew %d at %d.%09d: err = %v, want ErrInvalidCode", skew, tc.sec, tc.nsec, err)
			}
		}
	}
}

// After a code is accepted the application stores its step. If the clock then
// jumps backwards, nothing at or below that step is accepted again, whatever
// the size of the jump, and a code strictly newer is.
func TestVerifyStep_clockStepBackNeverReopensAUsedStep(t *testing.T) {
	secret, key := mustSecret(t)
	m := newTOTP(t, Config{SkewSteps: Int(2)})
	const base = 5_000_000
	atUnix(m, int64(base)*timeStep, 0)
	last, err := m.VerifyStep(secret, generateTOTP(key, base), 0)
	if err != nil || last != base {
		t.Fatalf("first acceptance = %d, %v", last, err)
	}
	for back := int64(0); back <= 4; back++ {
		atUnix(m, (int64(base)-back)*timeStep, 0)
		for s := int64(base) - 2; s <= int64(base)+2; s++ {
			_, err := m.VerifyStep(secret, generateTOTP(key, uint64(s)), last)
			inWindow := s >= int64(base)-back-2 && s <= int64(base)-back+2
			switch {
			case !inWindow:
				if !errors.Is(err, ErrInvalidCode) && !errors.Is(err, ErrCodeReused) {
					t.Errorf("back %d, step %d outside the window: %v", back, s, err)
				}
			case uint64(s) <= last:
				if !errors.Is(err, ErrCodeReused) {
					t.Errorf("back %d, step %d at or below the used step %d: %v, want ErrCodeReused", back, s, last, err)
				}
			default:
				if err != nil {
					t.Errorf("back %d, step %d above the used step: %v", back, s, err)
				}
			}
		}
	}
}

// A clock that jumps forward drops the window with it: a code from before the
// jump is dead once the jump is larger than the skew, however it is timed.
func TestVerifyStep_clockJumpForwardKillsOldCodes(t *testing.T) {
	secret, key := mustSecret(t)
	const skew, base = 1, 7_000_000
	m := newTOTP(t, Config{SkewSteps: Int(skew)})
	code := generateTOTP(key, base)
	for jump := int64(0); jump <= 6; jump++ {
		atUnix(m, (int64(base)+jump)*timeStep+timeStep-1, 999_999_999) // last instant of the step
		_, err := m.VerifyStep(secret, code, 0)
		if jump <= skew && err != nil {
			t.Errorf("jump of %d steps: refused: %v", jump, err)
		}
		if jump > skew && !errors.Is(err, ErrInvalidCode) {
			t.Errorf("jump of %d steps: %v, want ErrInvalidCode", jump, err)
		}
	}
}

// Whatever the clock reads, from just after the start of 1970 to the year 9999
// (the first steps of 1970 are left out, where a window would reach below step
// zero and step zero is the "no step used yet" value), a code is
// accepted if and only if it is the code of a step inside the window around the
// clock's step, computed here with plain integer arithmetic.
func TestVerifyStep_acceptsExactlyTheWindowAcrossTheWholeClockRange(t *testing.T) {
	secret, key := mustSecret(t)
	const skew = 2
	m := newTOTP(t, Config{SkewSteps: Int(skew)})
	for _, sec := range []int64{
		(skew+1)*timeStep + 0, (skew+1)*timeStep + 29, 1e6, 1_700_000_000, 4_102_444_800 /* 2100 */, 253_402_300_799, /* 9999-12-31 */
		1 << 40, 1 << 55,
	} {
		atUnix(m, sec, 0)
		cur := sec / timeStep
		for s := cur - skew - 2; s <= cur+skew+2; s++ {
			_, err := m.VerifyStep(secret, generateTOTP(key, uint64(s)), 0)
			inside := s >= cur-skew && s <= cur+skew
			if inside && err != nil {
				t.Errorf("clock %d: step %d (current %d) refused: %v", sec, s, cur, err)
			}
			if !inside && err == nil {
				t.Errorf("clock %d: step %d (current %d) accepted outside the window", sec, s, cur)
			}
		}
	}
}
