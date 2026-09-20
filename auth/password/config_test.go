package password

import (
	"errors"
	"strings"
	"testing"
)

// fastMod returns a Password built with the cheapest valid Argon2id parameters
// so Hash-based tests in this file do not spend seconds per call. The policy
// fields of cfg are preserved verbatim.
func fastMod(t *testing.T, cfg Config) *Password {
	t.Helper()
	cfg.Memory = 8 * 1024
	cfg.Iterations = 1
	cfg.Parallelism = 1
	mod, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return mod
}

// ---- DefaultConfig reproduces today's policy exactly ------------------------

func TestDefaultConfig_passwordPolicyLengths(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MinLength != 12 {
		t.Errorf("DefaultConfig().MinLength = %d, want 12", cfg.MinLength)
	}
	if cfg.MaxLength != 64 {
		t.Errorf("DefaultConfig().MaxLength = %d, want 64", cfg.MaxLength)
	}
}

func TestDefaultConfig_passwordPolicyRequiresAllClasses(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RequireUpper == nil || *cfg.RequireUpper != true {
		t.Error("DefaultConfig().RequireUpper must default to true (non-nil pointer to true)")
	}
	if cfg.RequireLower == nil || *cfg.RequireLower != true {
		t.Error("DefaultConfig().RequireLower must default to true (non-nil pointer to true)")
	}
	if cfg.RequireDigit == nil || *cfg.RequireDigit != true {
		t.Error("DefaultConfig().RequireDigit must default to true (non-nil pointer to true)")
	}
	if cfg.RequireSymbol == nil || *cfg.RequireSymbol != true {
		t.Error("DefaultConfig().RequireSymbol must default to true (non-nil pointer to true)")
	}
}

// TestDefaultConfig_passwordPolicyBoundaries covers the explicit boundary
// cases for the default policy: 11 rejected, 12 accepted, 64 accepted,
// 65 rejected. The "valid" seed (Aa1!) satisfies all four character classes
// so each length is the only thing changing.
func TestDefaultConfig_passwordPolicyBoundaries(t *testing.T) {
	mod := fastMod(t, Config{}) // zero policy fields → applyDefaults fills defaults

	base := "Aa1!"
	eleven := base + strings.Repeat("a", 7)     // 11 chars: too short
	twelve := base + strings.Repeat("a", 8)     // 12 chars: accepted (exactly MinLength)
	sixtyfour := base + strings.Repeat("a", 60) // 64 chars: accepted (exactly MaxLength)
	sixtyfive := base + strings.Repeat("a", 61) // 65 chars: too long

	if err := mod.ValidatePolicy(eleven); err == nil {
		t.Error("11-char password must be rejected under the default policy")
	}
	if err := mod.ValidatePolicy(twelve); err != nil {
		t.Errorf("12-char password must be accepted under the default policy, got %v", err)
	}
	if err := mod.ValidatePolicy(sixtyfour); err != nil {
		t.Errorf("64-char password must be accepted under the default policy, got %v", err)
	}
	if err := mod.ValidatePolicy(sixtyfive); err == nil {
		t.Error("65-char password must be rejected under the default policy")
	}
}

// ---- Configured MinLength is honoured and reported in the error --------------

func TestConfig_minLengthChangesFloor(t *testing.T) {
	// A password that passes the default (12 chars) must be rejected when
	// MinLength is raised to 16, and the error message must report 16.
	mod := fastMod(t, Config{MinLength: 16})

	pwd := "Abcdefgh1!" // 10 chars, satisfies classes but below the new floor
	if err := mod.ValidatePolicy(pwd); err == nil {
		t.Fatal("a 10-character password must be rejected when MinLength=16")
	} else if !strings.Contains(err.Error(), "16") {
		t.Errorf("error message must report the configured MinLength (16), got %q", err.Error())
	}
}

// ---- Configured *bool disables a class while leaving the others alone -------

func TestConfig_requireSymbolFalseAcceptsNoSymbol(t *testing.T) {
	// Three classes (upper, lower, digit) but no symbol. With RequireSymbol
	// turned off, the password is accepted; with it on, it would be rejected.
	no := false
	mod := fastMod(t, Config{RequireSymbol: &no})

	pwd := "Abcdefghijk1" // 12 chars, upper+lower+digit, no symbol
	if err := mod.ValidatePolicy(pwd); err != nil {
		t.Errorf("with RequireSymbol=false, a password with no symbol must be accepted, got %v", err)
	}
}

func TestConfig_requireSymbolFalseStillEnforcesOtherClasses(t *testing.T) {
	// With RequireSymbol turned off, a password that has no symbol but
	// also lacks one of the OTHER three classes must still be rejected  -
	// turning one class off must not silently turn the others off too.
	no := false
	mod := fastMod(t, Config{RequireSymbol: &no})

	cases := map[string]string{
		"no uppercase": "abcdefghijk1",
		"no lowercase": "ABCDEFGHIJK1",
		"no digit":     "Abcdefghijk!",
	}
	for name, pwd := range cases {
		t.Run(name, func(t *testing.T) {
			if err := mod.ValidatePolicy(pwd); err == nil {
				t.Errorf("%s must still be rejected when only RequireSymbol is off", name)
			}
		})
	}
}

// TestConfig_requireSymbolTrueRejectsNoSymbol is the negative direction:
// leaving the default in place (or explicitly setting *bool = true) must
// keep the old behaviour.
func TestConfig_requireSymbolTrueRejectsNoSymbol(t *testing.T) {
	yes := true
	mod := fastMod(t, Config{RequireSymbol: &yes})

	if err := mod.ValidatePolicy("Abcdefghijk1"); err == nil {
		t.Error("with RequireSymbol=true, a password with no symbol must be rejected")
	}
}

// ---- *bool pointer semantics: nil means "keep the default" ------------------

func TestApplyDefaults_fillsNilRequirePointersToTrue(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})

	want := true
	for name, p := range map[string]**bool{
		"RequireUpper":  &cfg.RequireUpper,
		"RequireLower":  &cfg.RequireLower,
		"RequireDigit":  &cfg.RequireDigit,
		"RequireSymbol": &cfg.RequireSymbol,
	} {
		if p == nil {
			t.Errorf("applyDefaults must fill %s with a non-nil pointer", name)
			continue
		}
		if **p != want {
			t.Errorf("applyDefaults must fill %s with a pointer to true, got %v", name, *p)
		}
	}
}

func TestApplyDefaults_preservesExplicitFalse(t *testing.T) {
	no := false
	cfg := applyDefaults(Config{
		Memory:        8 * 1024,
		Iterations:    1,
		Parallelism:   1,
		RequireUpper:  &no,
		RequireLower:  &no,
		RequireDigit:  &no,
		RequireSymbol: &no,
	})

	want := false
	for name, p := range map[string]**bool{
		"RequireUpper":  &cfg.RequireUpper,
		"RequireLower":  &cfg.RequireLower,
		"RequireDigit":  &cfg.RequireDigit,
		"RequireSymbol": &cfg.RequireSymbol,
	} {
		if p == nil {
			t.Errorf("applyDefaults must not nil-out %s when caller passed an explicit pointer", name)
			continue
		}
		if **p != want {
			t.Errorf("applyDefaults must preserve explicit false for %s, got %v", name, *p)
		}
	}
}

func TestApplyDefaults_fillsZeroLengths(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if cfg.MinLength != 12 {
		t.Errorf("applyDefaults MinLength = %d, want 12", cfg.MinLength)
	}
	if cfg.MaxLength != 64 {
		t.Errorf("applyDefaults MaxLength = %d, want 64", cfg.MaxLength)
	}
}

// ---- validateConfig refuses weakened or contradictory bounds ----------------

func TestValidateConfig_rejectsMinLengthBelowFloor(t *testing.T) {
	// 4 is below minPolicyLength (8); the validator must refuse instead of
	// silently letting the caller ship a weakened default.
	err := validateConfig(Config{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		MinLength:   4,
		MaxLength:   64,
	})
	if err == nil {
		t.Fatal("validateConfig must reject MinLength below 8")
	}
	if !strings.Contains(err.Error(), "min length") {
		t.Errorf("error must mention min length, got %v", err)
	}
}

func TestValidateConfig_rejectsMaxLengthBelowMinLength(t *testing.T) {
	// MaxLength smaller than MinLength is a contradiction: every input would
	// be rejected for both reasons at once, so the validator must refuse.
	err := validateConfig(Config{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		MinLength:   16,
		MaxLength:   12,
	})
	if err == nil {
		t.Fatal("validateConfig must reject MaxLength below MinLength")
	}
	if !strings.Contains(err.Error(), "max length") {
		t.Errorf("error must mention max length, got %v", err)
	}
}

func TestValidateConfig_rejectsOversizedMaxLength(t *testing.T) {
	// Above 1024 the bound becomes a CPU DoS: Argon2id hashes the whole input,
	// so the validator must refuse anything beyond the configured ceiling.
	err := validateConfig(Config{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		MinLength:   12,
		MaxLength:   1025,
	})
	if err == nil {
		t.Fatal("validateConfig must reject MaxLength above 1024")
	}
}

func TestNew_invalidPolicyConfigReturnsErrInvalidConfig(t *testing.T) {
	// A weakened config that slips past validateConfig would be silently
	// shipped in production. New must refuse it at construction time so the
	// failure is loud and at startup, not at first user registration.
	_, err := New(fakeProvider{}, Config{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		MinLength:   4, // below the floor
		MaxLength:   64,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New() with MinLength=4 must return ErrInvalidConfig, got %v", err)
	}
}

// TestBool_expressesBothStatesDistinctlyFromUnset pins the reason the policy
// fields are pointers at all. Bool(false) must reach checkPolicy as an off
// switch, while a nil field must keep the default on. A plain bool could not
// tell those apart, so if this test ever passes with a non-pointer field the
// distinction has been lost.
func TestBool_expressesBothStatesDistinctlyFromUnset(t *testing.T) {
	t.Parallel()

	if got := Bool(false); got == nil || *got {
		t.Fatalf("Bool(false) must point to false, got %v", got)
	}
	if got := Bool(true); got == nil || !*got {
		t.Fatalf("Bool(true) must point to true, got %v", got)
	}

	// No symbol, and long enough to clear the default floor.
	const noSymbol = "Passphrase123"

	unset := applyDefaults(Config{})
	if err := checkPolicy(noSymbol, unset); err == nil {
		t.Error("a nil RequireSymbol must keep today's behaviour, which rejects a password with no symbol")
	}

	off := applyDefaults(Config{RequireSymbol: Bool(false)})
	if err := checkPolicy(noSymbol, off); err != nil {
		t.Errorf("RequireSymbol set to Bool(false) must accept a password with no symbol, got %v", err)
	}

	// Turning one class off must not turn the others off with it.
	if err := checkPolicy("passphrase123", off); err == nil {
		t.Error("RequireUpper must still apply when only RequireSymbol was turned off")
	}
}

// TestNew_snapshotsPolicyPointers proves the policy the module was built with
// is owned by the module and not aliased through the caller's Config. Without
// the snapshot, mutating the caller's pointer after New would silently change
// what the built module accepts: flip cfg.RequireSymbol to false on the
// caller's struct, and ValidatePolicy("Abcdefghijk1") returns nil instead of
// the symbol-rule error it returned at construction.
func TestNew_snapshotsPolicyPointers(t *testing.T) {
	cfg := DefaultConfig()

	mod, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const noSymbol = "Abcdefghijk1"

	before := mod.ValidatePolicy(noSymbol)
	if before == nil {
		t.Fatal("baseline: Abcdefghijk1 must be rejected under the default policy")
	}
	if !errors.Is(before, ErrWeakPassword) {
		t.Fatalf("baseline error must wrap ErrWeakPassword, got %v", before)
	}
	if !strings.Contains(before.Error(), "special") {
		t.Fatalf("baseline must reject for the symbol rule, got %v", before)
	}

	// Flip the caller's pointer. With aliased storage the module would now
	// accept the password; with the snapshot it must still reject it.
	*cfg.RequireSymbol = false

	after := mod.ValidatePolicy(noSymbol)
	if after == nil {
		t.Fatal("after flipping the caller's *bool, the built module must keep the original policy")
	}
	if !errors.Is(after, ErrWeakPassword) {
		t.Fatalf("after error must wrap ErrWeakPassword, got %v", after)
	}
	if !strings.Contains(after.Error(), "special") {
		t.Fatalf("after must still reject for the same symbol rule, got %v", after)
	}
}
