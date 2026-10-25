package totp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp/internal/hotp"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
)

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

// New refuses what it cannot use (2026-09-25): a nil provider, logger or
// Keys panicked, a short refresh secret keyed recovery-code hashes with a
// value anyone can compute, and a second Config was dropped.
func TestNew_refusesWhatItCannotUse(t *testing.T) {
	short := fakeProvider{keys: fakeKeys{secret: make([]byte, 16)}}
	for name, tc := range map[string]struct {
		build func() (*TOTP, error)
		want  string
	}{
		"nil provider": {func() (*TOTP, error) { return New(nil) }, "provider is nil"},
		"nil logger":   {func() (*TOTP, error) { return New(nilLoggerProvider{newFakeProvider(t)}) }, "Logger() returned nil"},
		"nil keys":     {func() (*TOTP, error) { return New(fakeProvider{}) }, "Keys() returned nil"},
		"short secret": {func() (*TOTP, error) { return New(short) }, "refresh secret has wrong length: got 16"},
		"two configs":  {func() (*TOTP, error) { return New(newFakeProvider(t), Config{}, Config{}) }, "at most one Config"},
	} {
		_, err := tc.build()
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.want)
		}
	}
	if _, err := New(newFakeProvider(t), Config{}); err != nil {
		t.Fatalf("a real provider and one Config: %v", err)
	}
}

// A TOTP that New did not build has no pepper. Every method refuses on it
// (2026-09-25); before, HashRecoveryCode hashed under an empty key and
// VerifyRecoveryCode compared against such hashes.
func TestZeroValueTOTP_refusesEveryMethod(t *testing.T) {
	for name, mod := range map[string]*TOTP{"zero value": {}, "nil pointer": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := mod.Enroll("alice@example.com"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("Enroll = %v", err)
			}
			if _, err := mod.VerifyStep("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "123456", 0); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyStep = %v", err)
			}
			if err := mod.Verify(context.Background(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "123456", nopRecorder{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("Verify = %v", err)
			}
			if h, err := mod.HashRecoveryCode("ABCD1234-EFGH5678"); !errors.Is(err, ErrNotInitialised) || h != "" {
				t.Errorf("HashRecoveryCode = %q, %v", h, err)
			}
			// The hash anyone can compute under an empty key must not match.
			empty := (&TOTP{}).hashRecoveryCode("ABCD1234EFGH5678")
			if _, ok := mod.VerifyRecoveryCode("ABCD1234-EFGH5678", []string{empty}); ok {
				t.Error("VerifyRecoveryCode accepted a hash keyed with nothing")
			}
		})
	}
	// The built module still does all of it.
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if h, err := mod.HashRecoveryCode(enr.RecoveryCodes[0]); err != nil || h != enr.RecoveryHashes[0] {
		t.Fatalf("HashRecoveryCode on the built module = %q, %v", h, err)
	}
}

// Writing through the caller's SkewSteps pointer after New must not widen
// the window of the built module: at 1,000,000 four of five arbitrary codes
// verified before New copied the value.
func TestNew_copiesSkewSteps(t *testing.T) {
	cfg := Config{SkewSteps: Int(1)}
	mod := newTOTP(t, cfg)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := secret.Decode(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix()) / hotp.TimeStep
	old := hotp.Generate(key, now-120) // an hour ago

	*cfg.SkewSteps = 1_000_000
	if _, err := mod.VerifyStep(enr.Secret, old, 0); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("an hour-old code after the caller widened its int: %v, want ErrInvalidCode", err)
	}
	// The default skew of one step accepts the current code on either side of
	// a step boundary.
	if _, err := mod.VerifyStep(enr.Secret, hotp.Generate(key, now), 0); err != nil {
		t.Fatalf("the current code: %v, want accepted", err)
	}
}

// nopRecorder accepts every step; the zero-value checks never reach it.
type nopRecorder struct{}

func (nopRecorder) RecordIfNewer(context.Context, uint64) error { return nil }
