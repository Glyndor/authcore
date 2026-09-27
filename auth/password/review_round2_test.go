package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// Controls the 2026-09-25 review found working but unpinned: each could be
// deleted with the package suite green. Every test names what its control
// holds, and the acceptance case sits next to the refusal.

const nfdPassword = "Café-Espresso-99" // "é" as e + combining acute

// Hash normalises to NFC before hashing, as Verify does before comparing.
// Without it a user who registers with a decomposed password never signs
// in with the same input. The suite only covered NFC-hash, NFD-verify.
func TestHash_normalisesTheInputItHashes(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash(nfdPassword)
	if err != nil {
		t.Fatalf("Hash(NFD): %v", err)
	}
	for name, input := range map[string]string{"the NFD form": nfdPassword, "the NFC form": norm.NFC.String(nfdPassword)} {
		ok, err := mod.Verify(input, hash)
		if err != nil || !ok {
			t.Errorf("Verify(%s) = %v, %v; want true", name, ok, err)
		}
	}
	if ok, _ := mod.Verify("Cafe-Espresso-99", hash); ok {
		t.Fatal("a different password verified")
	}
}

// New snapshots each *bool policy field, so flipping the caller's value after
// New changes nothing. #437 pinned RequireSymbol only; three lines of four
// could go.
func TestNew_snapshotsEveryPolicyPointer(t *testing.T) {
	for name, tc := range map[string]struct {
		field    func(*Config) **bool
		password string // fails exactly that requirement
	}{
		"RequireUpper":  {func(c *Config) **bool { return &c.RequireUpper }, "abcdefghijk1!"},
		"RequireLower":  {func(c *Config) **bool { return &c.RequireLower }, "ABCDEFGHIJK1!"},
		"RequireDigit":  {func(c *Config) **bool { return &c.RequireDigit }, "Abcdefghijkl!"},
		"RequireSymbol": {func(c *Config) **bool { return &c.RequireSymbol }, "Abcdefghijk12"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			on := true
			*tc.field(&cfg) = &on
			mod, err := New(fakeProvider{}, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := mod.ValidatePolicy(tc.password); !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("before the flip, ValidatePolicy(%q) = %v, want ErrWeakPassword", tc.password, err)
			}
			on = false // the caller's variable, which the module must not read
			if err := mod.ValidatePolicy(tc.password); !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("after flipping the caller's %s, ValidatePolicy(%q) = %v, want still refused", name, tc.password, err)
			}
		})
	}
}

// The work-factor ceilings at New: a value past them is refused, one at
// them is accepted. Only the parse-time ceilings had tests.
func TestNew_refusesWorkFactorsPastTheCeilings(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg    Config
		reason string
	}{
		"memory past the ceiling":     {Config{Memory: maxMemory + 1, Iterations: 1, Parallelism: 1}, "memory must be at most"},
		"iterations past the ceiling": {Config{Memory: minMemory, Iterations: maxIterations + 1, Parallelism: 1}, "iterations must be at most"},
	} {
		_, err := New(fakeProvider{}, tc.cfg)
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.reason)
		}
	}
	if _, err := New(fakeProvider{}, Config{Memory: minMemory, Iterations: maxIterations, Parallelism: 1}); err != nil {
		t.Fatalf("iterations at the ceiling: %v, want accepted", err)
	}
}

// A stored hash whose parameter label is shorter than "label=" is refused,
// not sliced out of range. Without the prefix check in labeledValue, Verify
// panicked on "$argon2id$v$...", and the canonical-form check runs too late
// to help.
func TestVerify_refusesAHashWithABareLabel(t *testing.T) {
	mod := newMod(t)
	valid := phc(t, "argon2id", 19, minMemory, 3, 1)
	for name, hash := range map[string]string{
		"bare v": strings.Replace(valid, "v=19", "v", 1),
		"bare m": strings.Replace(valid, "m="+itoa(minMemory), "m", 1),
		"bare t": strings.Replace(valid, "t=3", "t", 1),
		"bare p": strings.Replace(valid, "p=1", "p", 1),
		"empty":  strings.Replace(valid, "v=19", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if hash == valid {
				t.Fatal("fixture unchanged")
			}
			ok, err := mod.Verify("Correct-Horse-Battery-9", hash)
			if ok || !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Verify = %v, %v; want false, ErrInvalidHash", ok, err)
			}
		})
	}
}

// Code points that render as nothing are refused, whichever class Unicode
// puts them in: the blank braille pattern is a symbol and satisfied
// RequireSymbol; the Hangul filler is a letter. A visible symbol with a
// variation selector stays accepted.
func TestValidatePolicy_refusesBlankRenderingCodePoints(t *testing.T) {
	mod := newMod(t)
	for name, pw := range map[string]string{
		"braille blank as the symbol": "Abcdefghijk1⠀",
		"hangul filler":               "Abcdefghijk1!ㅤ",
		"combining grapheme joiner":   "Abcdefghijk1!͏",
		"zero width joiner":           "Abcdefghijk1!‍",
	} {
		err := mod.ValidatePolicy(pw)
		if !errors.Is(err, ErrWeakPassword) || !errors.Is(err, ErrNonPrintableCharacter) {
			t.Errorf("%s: %v, want ErrNonPrintableCharacter", name, err)
		}
	}
	for name, pw := range map[string]string{
		"plain":                 "Abcdefghijk1!",
		"heart with selector":   "Abcdefghijk1❤️",
		"accented, real symbol": "Ábcdefghijk1!",
	} {
		if err := mod.ValidatePolicy(pw); err != nil {
			t.Errorf("%s: %v, want accepted", name, err)
		}
	}
}
