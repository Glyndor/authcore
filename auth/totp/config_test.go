package totp

import (
	"errors"
	"testing"
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
