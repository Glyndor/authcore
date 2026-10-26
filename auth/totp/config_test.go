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

// TestApplyDefaults_zeroConfigUsesTheDocumentedSkew pins the difference
// between "the caller left SkewSteps alone" and "the caller asked for no
// tolerance at all". They are the same value in a plain int, and getting
// them confused is a lockout rather than a weakening: a caller who built
// New(p) with no Config would silently get a zero-width window, and every
// user whose phone clock drifts a few seconds would fail to sign in while
// the field's own documentation promised one step of tolerance.
//
// This is why SkewSteps is a *int. If it is ever changed back to an int,
// the first assertion below fails.
func TestApplyDefaults_zeroConfigUsesTheDocumentedSkew(t *testing.T) {
	t.Parallel()

	if got := *applyDefaults(Config{}).SkewSteps; got != 1 {
		t.Errorf("New(p) with no Config must use the documented default of 1, got %d", got)
	}
	if got := *applyDefaults(DefaultConfig()).SkewSteps; got != 1 {
		t.Errorf("DefaultConfig must agree with the zero Config, got %d", got)
	}
	if got := *applyDefaults(Config{SkewSteps: Int(0)}).SkewSteps; got != 0 {
		t.Errorf("an explicit Int(0) must survive applyDefaults, got %d", got)
	}
}

// TestInt_returnsADistinctPointer guards the helper itself. Returning a
// pointer to a shared variable would let one Config mutate another.
func TestInt_returnsADistinctPointer(t *testing.T) {
	t.Parallel()

	a, b := Int(3), Int(3)
	if a == b {
		t.Fatal("Int must return a fresh pointer per call, not a shared one")
	}
	if *a != 3 || *b != 3 {
		t.Fatalf("Int(3) must point to 3, got %d and %d", *a, *b)
	}
	*a = 7
	if *b != 3 {
		t.Error("mutating one Int result changed another: the pointers are shared")
	}
}

// ---- validateConfig --------------------------------------------------------

func TestValidateConfig_Rejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"SkewSteps above cap", Config{SkewSteps: Int(11)}},
		{"negative SkewSteps", Config{SkewSteps: Int(-1)}},
		{"RecoveryCodeCount below floor", Config{RecoveryCodeCount: -1}},
		{"RecoveryCodeCount 51", Config{RecoveryCodeCount: 51}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(newFakeProvider(t), c.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New(%+v) = %v, want ErrInvalidConfig", c.cfg, err)
			}
		})
	}
}

func TestValidateConfig_RecoveryCodeCountZeroFallsBackToDefault(t *testing.T) {
	// RecoveryCodeCount 0 falls back to the default (10) via applyDefaults,
	// so it must NOT be rejected by validateConfig.
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 0}); err != nil {
		t.Errorf("RecoveryCodeCount 0 should default, got %v", err)
	}
}

func TestValidateConfig_Boundaries(t *testing.T) {
	// SkewSteps exactly at the cap (10) must be accepted.
	if _, err := New(newFakeProvider(t), Config{SkewSteps: Int(10)}); err != nil {
		t.Errorf("SkewSteps=10 should be accepted: %v", err)
	}
	// RecoveryCodeCount at the boundaries (1, 50) must be accepted.
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 1}); err != nil {
		t.Errorf("RecoveryCodeCount=1 should be accepted: %v", err)
	}
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 50}); err != nil {
		t.Errorf("RecoveryCodeCount=50 should be accepted: %v", err)
	}
}

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
