package totp_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// A code that was used is dead. The module reports the step a code belongs to
// and the application stores it; any code of that step or an older one is then
// a replay.
func TestHostile_TOTP_acceptedCodeCannotBeReplayed(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		code := codeAt(t, secret, step)
		got, err := m.VerifyStep(secret, code, 0)
		if err != nil || got != step {
			return fmt.Sprintf("control: VerifyStep = %d, %v; want %d, nil", got, err, step)
		}
		// The same code again, with the step recorded.
		if _, err := m.VerifyStep(secret, code, got); !errors.Is(err, totp.ErrCodeReused) {
			return fmt.Sprintf("replay of the accepted code: %v, want ErrCodeReused", err)
		}
		// An older code, valid inside the window, is also dead once a newer
		// step is recorded: nothing can walk the high-water mark backwards.
		older := codeAt(t, secret, step-1)
		if _, err := m.VerifyStep(secret, older, got); !errors.Is(err, totp.ErrCodeReused) {
			return fmt.Sprintf("older in-window code after a newer step: %v, want ErrCodeReused", err)
		}
		// A code the window allows from the future is still fresh.
		future := codeAt(t, secret, step+1)
		if s, err := m.VerifyStep(secret, future, got); err != nil || s != step+1 {
			return fmt.Sprintf("next step's code = %d, %v; want %d, nil", s, err, step+1)
		}
		return ""
	})
}

// The recorder is the application's half of the contract. Many requests with
// the same code at once, which is what a code intercepted on the wire looks
// like next to the legitimate request, produce exactly one success.
func TestHostile_TOTP_concurrentReplayOfOneCodeYieldsOneAcceptance(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		code := codeAt(t, secret, step)
		rec := &memRecorder{}
		const attackers = 64
		var (
			wg       sync.WaitGroup
			start    = make(chan struct{})
			accepted atomic.Int64
			reused   atomic.Int64
			other    atomic.Int64
		)
		for i := 0; i < attackers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				switch err := m.Verify(context.Background(), secret, code, rec); {
				case err == nil:
					accepted.Add(1)
				case errors.Is(err, totp.ErrCodeReused):
					reused.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if accepted.Load() != 1 || reused.Load() != attackers-1 || other.Load() != 0 {
			return fmt.Sprintf("accepted=%d reused=%d other=%d of %d", accepted.Load(), reused.Load(), other.Load(), attackers)
		}
		return ""
	})
}

// A recorder that cannot answer is not a recorder that said yes: the code is
// refused with the recorder's error, and a code that fails verification never
// reaches the recorder at all.
func TestHostile_TOTP_recorderFailureFailsClosed(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	down := errors.New("postgres: connection refused")

	atStableStep(t, func(step uint64) string {
		code := codeAt(t, secret, step)

		rec := &memRecorder{fail: down}
		err := m.Verify(context.Background(), secret, code, rec)
		if !errors.Is(err, down) || errors.Is(err, totp.ErrCodeReused) {
			return fmt.Sprintf("a failing recorder: %v, want the recorder's error", err)
		}

		rec = &memRecorder{}
		for _, bad := range []string{"000000", "12345", "abcdef", ""} {
			if bad == code {
				continue
			}
			if err := m.Verify(context.Background(), secret, bad, rec); err == nil {
				return fmt.Sprintf("code %q accepted", bad)
			}
		}
		if rec.hits != 0 {
			return fmt.Sprintf("the recorder was called %d times for codes that do not verify", rec.hits)
		}
		return ""
	})
}

// A cancelled request is refused before any code is consumed, so cancelling
// cannot burn a user's code, and a missing recorder is an error rather than a
// silent skip of the replay check.
func TestHostile_TOTP_verifyRefusesWithoutAReplayGuard(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		code := codeAt(t, secret, step)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rec := &memRecorder{}
		if err := m.Verify(ctx, secret, code, rec); !errors.Is(err, context.Canceled) {
			return fmt.Sprintf("cancelled context: %v, want context.Canceled", err)
		}
		if rec.hits != 0 {
			return "a cancelled request reached the recorder"
		}

		var nilRec *memRecorder
		for name, r := range map[string]totp.StepRecorder{"nil interface": nil, "typed nil": nilRec} {
			if err := m.Verify(context.Background(), secret, code, r); !errors.Is(err, totp.ErrStepRecorderRequired) {
				return fmt.Sprintf("%s recorder: %v, want ErrStepRecorderRequired", name, err)
			}
		}
		return ""
	})
}

// The window is the configured skew and no wider. Codes from further away are
// not valid, in either direction, and skew 0 accepts only the current step.
func TestHostile_TOTP_windowIsExactlyTheConfiguredSkew(t *testing.T) {
	secret := sharedSecret(t)
	for _, skew := range []int{0, 1, 3} {
		m := newModule(t, totp.Config{SkewSteps: totp.Int(skew)})
		atStableStep(t, func(step uint64) string {
			for d := -5; d <= 5; d++ {
				code := codeAt(t, secret, uint64(int64(step)+int64(d)))
				_, err := m.VerifyStep(secret, code, 0)
				inside := d >= -skew && d <= skew
				if inside && err != nil {
					return fmt.Sprintf("skew %d: step offset %d refused: %v", skew, d, err)
				}
				if !inside && !errors.Is(err, totp.ErrInvalidCode) {
					// A code that happens to equal one inside the window is a
					// 1 in 10^6 coincidence the oracle cannot tell apart.
					same := false
					for e := -skew; e <= skew; e++ {
						same = same || codeAt(t, secret, uint64(int64(step)+int64(e))) == code
					}
					if !same {
						return fmt.Sprintf("skew %d: step offset %d = %v, want ErrInvalidCode", skew, d, err)
					}
				}
			}
			return ""
		})
	}
}

// Skew is bounded at construction, so no configuration turns the window into
// "any code works for the next hour".
func TestHostile_TOTP_skewAndRecoveryCountAreBounded(t *testing.T) {
	for name, cfg := range map[string]totp.Config{
		"skew 11":             {SkewSteps: totp.Int(11)},
		"skew negative":       {SkewSteps: totp.Int(-1)},
		"skew huge":           {SkewSteps: totp.Int(1 << 30)},
		"recovery count 51":   {RecoveryCodeCount: 51},
		"recovery count -1":   {RecoveryCodeCount: -1},
		"recovery count huge": {RecoveryCodeCount: 1 << 30},
	} {
		if _, err := totp.New(newProvider(t), cfg); !errors.Is(err, totp.ErrInvalidConfig) {
			t.Errorf("%s: totp.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := totp.New(newProvider(t), totp.Config{SkewSteps: totp.Int(10), RecoveryCodeCount: 50}); err != nil {
		t.Errorf("control: the maximum values were refused: %v", err)
	}
}

// A code that is not six ASCII digits is refused as malformed before any
// secret is decoded or any hash is computed: whitespace, other scripts' digits,
// signs, separators and length variations included.
func TestHostile_TOTP_malformedCodesAreRefusedAsMalformed(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	for name, code := range map[string]string{
		"empty":               "",
		"five digits":         "12345",
		"seven digits":        "1234567",
		"leading space":       " 123456",
		"trailing space":      "123456 ",
		"inner space":         "123 456",
		"trailing newline":    "123456\n",
		"trailing NUL":        "123456\x00",
		"tab":                 "123\t456",
		"hyphen":              "123-456",
		"plus sign":           "+12345",
		"minus sign":          "-12345",
		"decimal point":       "1.23456",
		"hex prefix":          "0x1234",
		"hex digits":          "12345a",
		"letters":             "abcdef",
		"arabic-indic digits": "\u0661\u0662\u0663\u0664\u0665\u0666",
		"fullwidth digits":    "\uff11\uff12\uff13\uff14\uff15\uff16",
		"superscript digits":  "\u00b9\u00b2\u00b3\u2074\u2075\u2076",
		"combining mark":      "12345\u0301",
		"zero width joiner":   "12345\u200d6",
		"one MiB of NULs":     string(make([]byte, 1<<20)),
		"six digits plus ten": "1234567890",
		"json":                `["123456"]`,
	} {
		if err := m.Verify(context.Background(), secret, code, &memRecorder{}); !errors.Is(err, totp.ErrMalformedCode) {
			t.Errorf("%s: Verify = %v, want ErrMalformedCode", name, err)
		}
		if _, err := m.VerifyStep(secret, code, 0); !errors.Is(err, totp.ErrMalformedCode) {
			t.Errorf("%s: VerifyStep = %v, want ErrMalformedCode", name, err)
		}
	}
}

// A wrong code is a mismatch, distinct from a malformed one, so the caller can
// count failed attempts without parsing text.
func TestHostile_TOTP_wrongCodeIsAMismatchNotAFormatError(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		valid := map[string]bool{}
		for d := -1; d <= 1; d++ {
			valid[codeAt(t, secret, uint64(int64(step)+int64(d)))] = true
		}
		checked := 0
		for _, c := range []string{"000000", "111111", "123456", "999999", "000001"} {
			if valid[c] {
				continue
			}
			checked++
			if _, err := m.VerifyStep(secret, c, 0); !errors.Is(err, totp.ErrInvalidCode) {
				return fmt.Sprintf("%s: %v, want ErrInvalidCode", c, err)
			}
		}
		// A code that matches in five of six places is as wrong as any other.
		right := codeAt(t, secret, step)
		for pos := 0; pos < 6; pos++ {
			b := []byte(right)
			b[pos] = '0' + (b[pos]-'0'+1)%10
			near := string(b)
			if valid[near] {
				continue
			}
			checked++
			if _, err := m.VerifyStep(secret, near, 0); !errors.Is(err, totp.ErrInvalidCode) {
				return fmt.Sprintf("%s (right code %s with position %d changed): %v, want ErrInvalidCode", near, right, pos, err)
			}
		}
		if checked == 0 {
			return "no wrong code was checked"
		}
		return ""
	})
}
