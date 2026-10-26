// Package mfa attacks the second factor as an application runs it: a TOTP code
// verified through a per-enrollment StepRecorder, recovery codes consumed by a
// delete that re-checks the hash, several accounts in one table, and many
// requests at once. The adversary has seen codes and recovery codes of its own
// accounts and tries them on another, again, and in parallel.
package mfa

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

var ctx = context.Background()

func newModule(t *testing.T, cfg totp.Config) *totp.TOTP {
	t.Helper()
	return hostiletest.NewEnv(t).TOTP(t, cfg)
}

// A code is spent by being used: the recorder advances to its step, the same
// code is refused afterwards, and so is every code of an earlier step, even
// though each of them is still inside the window.
func TestE2E_MFA_aCodeIsSingleUseAndTimeNeverGoesBack(t *testing.T) {
	m := newModule(t, totp.Config{})
	hostiletest.AtStableStep(t, func(step uint64) string {
		acc := hostiletest.Enroll(t, m, "alice@example.com")
		code := func(s uint64) string { return hostiletest.CodeAt(t, acc.Secret, s) }

		if err := m.Verify(ctx, acc.Secret, code(step-1), acc); err != nil {
			return "code of the previous step refused: " + err.Error()
		}
		if err := m.Verify(ctx, acc.Secret, code(step-1), acc); !errors.Is(err, totp.ErrCodeReused) {
			return "same code twice = " + errString(err)
		}
		if err := m.Verify(ctx, acc.Secret, code(step+1), acc); err != nil {
			return "code of the next step refused: " + err.Error()
		}
		for name, s := range map[string]uint64{"current": step, "previous": step - 1, "next": step + 1} {
			if err := m.Verify(ctx, acc.Secret, code(s), acc); !errors.Is(err, totp.ErrCodeReused) {
				return name + " step after the next one was spent = " + errString(err)
			}
		}
		if acc.LastStep() != step+1 {
			return "recorder did not stop at the highest step"
		}
		return ""
	})
}

func errString(err error) string {
	if err == nil {
		return "<nil>, want a refusal"
	}
	return err.Error()
}

// The window is the configured skew and no wider, and a refusal leaves the
// recorder where it was.
func TestE2E_MFA_theWindowIsTheSkewAndARefusalAdvancesNothing(t *testing.T) {
	for _, skew := range []int{0, 1, 3} {
		m := newModule(t, totp.Config{SkewSteps: totp.Int(skew)})
		hostiletest.AtStableStep(t, func(step uint64) string {
			for _, off := range []int{-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5} {
				fresh := hostiletest.Enroll(t, m, "bob@example.com")
				code := hostiletest.CodeAt(t, fresh.Secret, uint64(int64(step)+int64(off)))
				err := m.Verify(ctx, fresh.Secret, code, fresh)
				inside := off >= -skew && off <= skew
				switch {
				case inside && err != nil:
					return "skew " + strconv.Itoa(skew) + " offset " + strconv.Itoa(off) + " refused: " + err.Error()
				case !inside && !errors.Is(err, totp.ErrInvalidCode):
					return "skew " + strconv.Itoa(skew) + " offset " + strconv.Itoa(off) + " = " + errString(err)
				case !inside && fresh.LastStep() != 0:
					return "a refused code advanced the recorder"
				}
			}
			return ""
		})
	}
}

// A code from one account is nothing at another: the secret binds it, and the
// failed attempt neither advances the victim's recorder nor spends the owner's
// code.
func TestE2E_MFA_aCodeDoesNotCrossAccounts(t *testing.T) {
	m := newModule(t, totp.Config{})
	hostiletest.AtStableStep(t, func(step uint64) string {
		a := hostiletest.Enroll(t, m, "a@example.com")
		b := hostiletest.Enroll(t, m, "b@example.com")
		codeA := hostiletest.CodeAt(t, a.Secret, step)
		if codeA == hostiletest.CodeAt(t, b.Secret, step) || codeA == hostiletest.CodeAt(t, b.Secret, step-1) || codeA == hostiletest.CodeAt(t, b.Secret, step+1) {
			return "" // a one in a million coincidence between two random secrets proves nothing
		}
		if err := m.Verify(ctx, b.Secret, codeA, b); !errors.Is(err, totp.ErrInvalidCode) {
			return "A's code at B = " + errString(err)
		}
		if b.LastStep() != 0 || a.LastStep() != 0 {
			return "a cross-account attempt moved a recorder"
		}
		if err := m.Verify(ctx, a.Secret, codeA, a); err != nil {
			return "the owner's code after the attack = " + errString(err)
		}
		return ""
	})
}

// What is not a code is refused before the recorder hears of it, and a storage
// failure is neither acceptance nor a replay.
func TestE2E_MFA_malformedInputsAndAFailingStoreNeverAccept(t *testing.T) {
	m := newModule(t, totp.Config{})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	for _, code := range []string{"", "12345", "1234567", "12345a", " 123456", "123456 ", "١٢٣٤٥٦", acc.Codes[0]} {
		if err := m.Verify(ctx, acc.Secret, code, acc); err == nil {
			t.Errorf("code %q accepted", code)
		}
	}
	if acc.LastStep() != 0 {
		t.Error("a malformed code reached the recorder")
	}
	hostiletest.AtStableStep(t, func(step uint64) string {
		down := errors.New("connection lost")
		err := m.Verify(ctx, acc.Secret, hostiletest.CodeAt(t, acc.Secret, step), failing{down})
		switch {
		case err == nil:
			return "accepted while the store was down"
		case errors.Is(err, totp.ErrCodeReused):
			return "a storage failure reported as a replay"
		case !errors.Is(err, down):
			return "the storage error was lost: " + err.Error()
		}
		return ""
	})
	if err := m.Verify(ctx, acc.Secret, "000000", nil); !errors.Is(err, totp.ErrStepRecorderRequired) {
		t.Errorf("nil recorder = %v, want ErrStepRecorderRequired", err)
	}
	var typedNil *hostiletest.Account
	if err := m.Verify(ctx, acc.Secret, "000000", typedNil); !errors.Is(err, totp.ErrStepRecorderRequired) {
		t.Errorf("typed nil recorder = %v, want ErrStepRecorderRequired", err)
	}
}

type failing struct{ err error }

func (f failing) RecordIfNewer(context.Context, uint64) error { return f.err }
