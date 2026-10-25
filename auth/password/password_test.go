package password

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore"
)

// ---- test infrastructure ----------------------------------------------------

// fakeProvider satisfies authcore.Provider with a silent logger and no keys.
type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Password {
	t.Helper()
	mod, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return mod
}

// ---- New() ------------------------------------------------------------------

func TestNew_noArgsUsesDefaults(t *testing.T) {
	_, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New() with no config error = %v", err)
	}
}

func TestNew_explicitConfigSucceeds(t *testing.T) {
	_, err := New(fakeProvider{}, DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_zeroConfigSucceedsBecauseDefaultsAreApplied(t *testing.T) {
	_, err := New(fakeProvider{}, Config{})
	if err != nil {
		t.Fatalf("New(Config{}) error = %v; applyDefaults should have filled zero values", err)
	}
}

func TestNew_tooLowMemoryReturnsErrInvalidConfig(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: 1024}) // below 8 MiB minimum
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_zeroIterationsAreFilledByDefaults(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: DefaultConfig().Memory, Parallelism: 2})
	if err != nil {
		t.Fatalf("expected nil error when Iterations=0, got %v", err)
	}
}

func TestNew_zeroParallelismIsFilledByDefaults(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: DefaultConfig().Memory, Iterations: 1})
	if err != nil {
		t.Fatalf("expected nil error when Parallelism=0, got %v", err)
	}
}

// ---- Name() -----------------------------------------------------------------

func TestName(t *testing.T) {
	mod := newMod(t)
	if mod.Name() != "password" {
		t.Errorf("Name() = %q, want %q", mod.Name(), "password")
	}
}

// ---- Hash() — policy enforcement --------------------------------------------

func TestHash_weakPasswordReturnsErrWeakPassword(t *testing.T) {
	mod := newMod(t)

	cases := []struct {
		name string
		pwd  string
	}{
		{"too short", "Aa1!"},
		{"too long", "Aa1!" + strings.Repeat("x", 61)},
		{"no uppercase", "lowercase1!aaa"},
		{"no lowercase", "UPPERCASE1!AAA"},
		{"no digit", "NoDigitHere!!!"},
		{"no special", "NoSpecial1Abcde"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mod.Hash(tc.pwd)
			if !errors.Is(err, ErrWeakPassword) {
				t.Errorf("Hash(%q) error = %v, want ErrWeakPassword", tc.pwd, err)
			}
		})
	}
}

func TestHash_strongPasswordSucceeds(t *testing.T) {
	mod := newMod(t)
	_, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Errorf("Hash(strong password) error = %v, want nil", err)
	}
}

// ---- checkPolicy() ----------------------------------------------------------

func TestCheckPolicy_boundaryLengths(t *testing.T) {
	base := "Aa1!"         // 4-char valid seed - pad to reach target length
	cfg := DefaultConfig() // 12..64, all classes required

	exactly12 := base + strings.Repeat("a", 8)
	if err := checkPolicy(exactly12, cfg); err != nil {
		t.Errorf("12-char password rejected: %v", err)
	}

	exactly64 := base + strings.Repeat("a", 60)
	if err := checkPolicy(exactly64, cfg); err != nil {
		t.Errorf("64-char password rejected: %v", err)
	}

	tooShort := base + strings.Repeat("a", 7) // 11 chars
	if checkPolicy(tooShort, cfg) == nil {
		t.Error("11-char password should be rejected")
	}

	tooLong := base + strings.Repeat("a", 61) // 65 chars
	if checkPolicy(tooLong, cfg) == nil {
		t.Error("65-char password should be rejected")
	}
}

// ---- ValidatePolicy() -------------------------------------------------------

func TestValidatePolicy_validPassword(t *testing.T) {
	p, _ := New(fakeProvider{})
	if err := p.ValidatePolicy("Correct-Horse-9!"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidatePolicy_weakPassword(t *testing.T) {
	p, _ := New(fakeProvider{})
	if err := p.ValidatePolicy("weak"); err == nil {
		t.Error("expected error for weak password, got nil")
	}
}

func TestValidatePolicy_nfcAndNfdFormsAgree(t *testing.T) {
	p, _ := New(fakeProvider{})

	// Same logical password in NFC (precomposed "é") and NFD (base "e" +
	// combining acute). Both byte sequences represent the same visual
	// password, so ValidatePolicy must treat them identically — accepting
	// or rejecting both the same way. Before NFC normalisation was added,
	// byte-level length counts and codepoint-level iteration could diverge
	// on these two forms.
	nfc := "Contraseña-Seguro9!"       // "ñ" as single codepoint U+00F1
	nfd := "Contrasen\u0303a-Seguro9!" // "ñ" as "n" + combining tilde U+0303

	if nfc == nfd {
		t.Fatal("test setup error: NFC and NFD forms are identical")
	}
	errNFC := p.ValidatePolicy(nfc)
	errNFD := p.ValidatePolicy(nfd)
	if (errNFC == nil) != (errNFD == nil) {
		t.Errorf("ValidatePolicy disagrees between NFC and NFD forms: NFC=%v, NFD=%v", errNFC, errNFD)
	}
}

// TestValidatePolicy_lengthBoundaryStraddlesNFCAndNFD pins the normalisation
// at the length boundary. With a length-only policy (12..64 runes, no class
// requirements), a password of 64 precomposed "ñ" characters is 64 runes in
// NFC and at the cap. The same visual password written with one of those
// characters in NFD ("n" + combining tilde) is 65 runes without
// normalisation, over the cap, and 64 runes after normalisation. Without
// NFC normalisation the policy would reject the NFD form even though the
// NFC form passes, the bug a caller from a system that produces decomposed
// text would hit on the first attempt to register.
//
// The acceptance twin: the NFC form must also pass, otherwise a test that
// rejected both forms would still be a pass.
func TestValidatePolicy_lengthBoundaryStraddlesNFCAndNFD(t *testing.T) {
	// Length-only policy: the class requirements would otherwise force the
	// fixture to include an uppercase letter, a lowercase letter, a digit
	// and a symbol, none of which matters for the boundary being tested.
	off := false
	cfg := DefaultConfig()
	cfg.MinLength = 12
	cfg.MaxLength = 64
	cfg.RequireUpper = &off
	cfg.RequireLower = &off
	cfg.RequireDigit = &off
	cfg.RequireSymbol = &off

	p, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 64 precomposed ñ: exactly 64 runes in NFC, at the cap.
	nfcAtCap := strings.Repeat("ñ", 64)
	if utf8.RuneCountInString(nfcAtCap) != 64 {
		t.Fatalf("test setup: NFC fixture should be 64 runes, got %d", utf8.RuneCountInString(nfcAtCap))
	}
	if err := p.ValidatePolicy(nfcAtCap); err != nil {
		t.Fatalf("64-rune NFC ñ-chain should be at the cap and accepted, got %v", err)
	}

	// 63 precomposed ñ plus one decomposed ñ: 63 + 2 = 65 runes without
	// normalisation, which would be refused; 63 + 1 = 64 runes after
	// normalisation, which is at the cap and must be accepted.
	nfdOverCap := strings.Repeat("ñ", 63) + "n\u0303"
	if got := utf8.RuneCountInString(nfdOverCap); got != 65 {
		t.Fatalf("test setup: expected 65 runes before normalisation, got %d", got)
	}
	if err := p.ValidatePolicy(nfdOverCap); err != nil {
		t.Errorf("NFD form over the rune cap before normalisation must pass after NFC normalisation, got %v", err)
	}

	// Acceptance twin: the NFD form, after explicit NFC normalisation, is
	// still 64 runes and still passes, so the policy is unchanged when the
	// input already happens to be NFC.
	if err := p.ValidatePolicy(norm.NFC.String(nfdOverCap)); err != nil {
		t.Errorf("explicitly NFC-normalised form should be accepted too, got %v", err)
	}
}

// ---- DefaultConfig() --------------------------------------------------------

func TestDefaultConfig_values(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Memory != 64*1024 {
		t.Errorf("DefaultConfig().Memory = %d, want %d", cfg.Memory, 64*1024)
	}
	if cfg.Iterations != 3 {
		t.Errorf("DefaultConfig().Iterations = %d, want 3", cfg.Iterations)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("DefaultConfig().Parallelism = %d, want 2", cfg.Parallelism)
	}
}

// ---- applyDefaults() --------------------------------------------------------

func TestApplyDefaults_fillsZeroMemory(t *testing.T) {
	cfg := applyDefaults(Config{Iterations: 1, Parallelism: 1})
	if cfg.Memory != DefaultConfig().Memory {
		t.Errorf("applyDefaults zero Memory = %d, want %d", cfg.Memory, DefaultConfig().Memory)
	}
}

func TestApplyDefaults_fillsZeroIterations(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Parallelism: 1})
	if cfg.Iterations != DefaultConfig().Iterations {
		t.Errorf("applyDefaults zero Iterations = %d, want %d", cfg.Iterations, DefaultConfig().Iterations)
	}
}

func TestApplyDefaults_fillsZeroParallelism(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Iterations: 1})
	if cfg.Parallelism != DefaultConfig().Parallelism {
		t.Errorf("applyDefaults zero Parallelism = %d, want %d", cfg.Parallelism, DefaultConfig().Parallelism)
	}
}
