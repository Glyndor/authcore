package totp_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// The skew window is fixed when the module is built. Writing through the
// pointer the caller handed to New must not widen it afterwards.
func TestHostile_TOTP_windowIsFixedAtConstruction(t *testing.T) {
	skew := totp.Int(1)
	m := newModule(t, totp.Config{SkewSteps: skew})
	*skew = 100_000
	secret := sharedSecret(t)
	atStableStep(t, func(step uint64) string {
		if _, err := m.VerifyStep(secret, codeAt(t, secret, step+1), 0); err != nil {
			return fmt.Sprintf("control: next step inside the window: %v", err)
		}
		for _, off := range []uint64{2, 50, 5_000} {
			if _, err := m.VerifyStep(secret, codeAt(t, secret, step-off), 0); !errors.Is(err, totp.ErrInvalidCode) {
				return fmt.Sprintf("code %d steps old after widening the caller's pointer: %v, want ErrInvalidCode", off, err)
			}
		}
		return ""
	})
}

// Every refusal reports step 0, so a caller that stores the returned step
// without looking at the error cannot move its high-water mark.
func TestHostile_TOTP_refusalsReportStepZero(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	var nilModule *totp.TOTP
	atStableStep(t, func(step uint64) string {
		code := codeAt(t, secret, step)
		cases := []struct {
			name   string
			module *totp.TOTP
			secret string
			code   string
			last   uint64
			want   error
		}{
			{"malformed code", m, secret, "12ab56", 0, totp.ErrMalformedCode},
			{"invalid secret", m, "not-base32!", code, 0, totp.ErrInvalidSecret},
			{"wrong code", m, secret, codeAt(t, secret, step+500), 0, totp.ErrInvalidCode},
			{"replayed step", m, secret, code, step + 10, totp.ErrCodeReused},
			{"uninitialised module", nilModule, secret, code, 0, totp.ErrNotInitialised},
		}
		for _, c := range cases {
			got, err := c.module.VerifyStep(c.secret, c.code, c.last)
			if !errors.Is(err, c.want) || got != 0 {
				return fmt.Sprintf("%s: step %d, err %v; want step 0, %v", c.name, got, err, c.want)
			}
		}
		return ""
	})
}

// A miss reports index 0 together with false, whatever the list holds, so a
// caller that ignores the flag never reaches for a stray row.
func TestHostile_TOTP_recoveryMissReportsIndexZero(t *testing.T) {
	m := newModule(t)
	enr, err := m.Enroll("miss@example.com")
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.HashRecoveryCode("AAAAAAAA-BBBBBBBB")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"CCCCCCCC-DDDDDDDD", "", " - "} {
		if idx, ok := m.VerifyRecoveryCode(code, append([]string{other}, enr.RecoveryHashes...)); ok || idx != 0 {
			t.Fatalf("code %q: got (%d, %v), want (0, false)", code, idx, ok)
		}
	}
}
