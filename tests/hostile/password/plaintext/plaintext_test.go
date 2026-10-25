// Package plaintext attacks the password itself: invisible characters, sizes,
// Unicode normalisation and policy bounds.
package plaintext

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// Characters that look like nothing, or that change how neighbours render, are
// refused at the policy, so two passwords that look identical on screen cannot
// differ by an invisible byte, and a control byte cannot reach a downstream
// parser.
func TestHostile_Plaintext_invisibleAndControlCharactersAreRefused(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	if err := m.ValidatePolicy(hostiletest.Strong); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string]string{
		"NUL":                     "\x00",
		"bell":                    "\x07",
		"backspace":               "\x08",
		"tab":                     "\t",
		"newline":                 "\n",
		"carriage return":         "\r",
		"escape":                  "\x1b",
		"delete":                  "\x7f",
		"next line":               "\u0085",
		"C1 control":              "\u009f",
		"line separator":          "\u2028",
		"paragraph separator":     "\u2029",
		"zero width space":        "\u200b",
		"zero width joiner":       "\u200d",
		"zero width non-joiner":   "\u200c",
		"word joiner":             "\u2060",
		"byte order mark":         "\ufeff",
		"soft hyphen":             "\u00ad",
		"left-to-right mark":      "\u200e",
		"right-to-left mark":      "\u200f",
		"bidi override":           "\u202e",
		"bidi isolate":            "\u2066",
		"hangul filler":           "\u3164",
		"halfwidth hangul filler": "\uffa0",
		"braille blank":           "\u2800",
		"tag character":           "\U000e0041",
		"replacement char":        "\ufffd",
		"invalid UTF-8 byte":      "\xff",
		"truncated UTF-8":         "\xe2\x82",
		"surrogate half":          "\xed\xa0\x80",
		"private use":             "\ue000",
		"noncharacter":            "\ufdd0",
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			pw := hostiletest.Strong[:6] + r + hostiletest.Strong[6:]
			if err := m.ValidatePolicy(pw); !errors.Is(err, password.ErrWeakPassword) || !errors.Is(err, password.ErrNonPrintableCharacter) {
				t.Fatalf("ValidatePolicy = %v, want ErrWeakPassword wrapping ErrNonPrintableCharacter", err)
			}
			if h, err := m.Hash(pw); h != "" || !errors.Is(err, password.ErrWeakPassword) {
				t.Fatalf("Hash = %q, %v; want no hash and ErrWeakPassword", h, err)
			}
		})
	}
}

// The length limit counts characters, after normalization, and the pair of
// boundaries is exact. A huge input is refused without a hashing cost.
func TestHostile_Plaintext_lengthBoundsAreExactAndCheap(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	pad := func(n int) string { return "Aa1!" + strings.Repeat("x", n-4) }

	for n, ok := range map[int]bool{11: false, 12: true, 64: true, 65: false} {
		err := m.ValidatePolicy(pad(n))
		if (err == nil) != ok {
			t.Errorf("%d characters: ValidatePolicy = %v, want accepted=%v", n, err, ok)
		}
	}

	// Multi-byte characters count once, so 64 of them are within the limit
	// although they are 256 bytes, and 65 are over it.
	wide := "Aa1!" + strings.Repeat("\U0001F600", 60)
	if utf8Len(wide) != 64 {
		t.Fatal("test bug: fixture is not 64 characters")
	}
	if err := m.ValidatePolicy(wide); err != nil {
		t.Errorf("64 characters in 244 bytes refused: %v", err)
	}
	if err := m.ValidatePolicy(wide + "x"); err == nil {
		t.Error("65 characters accepted")
	}

	// The limit applies to the NFC form, which is what is hashed: 40 accented
	// letters spelled as base letter plus combining mark are 80 characters
	// as typed and 40 once composed.
	decomposed := "Aa1!" + strings.Repeat("e\u0301", 40)
	if utf8Len(decomposed) != 84 {
		t.Fatal("test bug: fixture is not 84 characters")
	}
	if err := m.ValidatePolicy(decomposed); err != nil {
		t.Errorf("a password of 44 composed characters was refused for its decomposed length: %v", err)
	}
	if h, err := m.Hash(decomposed); err != nil || h == "" {
		t.Errorf("Hash of the decomposed spelling: %q, %v", h, err)
	}

	for _, size := range []int{1 << 20, 16 << 20} {
		huge := "Aa1!" + strings.Repeat("x", size)
		start := time.Now()
		h, err := m.Hash(huge)
		if h != "" || !errors.Is(err, password.ErrWeakPassword) {
			t.Fatalf("%d byte password: %q, %v; want ErrWeakPassword", size, h, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%d byte password took %v to refuse", size, d)
		}
	}
}

func utf8Len(s string) int { return len([]rune(s)) }

// The module hashes the NFC form. Composed and decomposed spellings of one
// password are one password, so a user is not locked out by the way their
// keyboard or OS composes a character. The module does not go further and fold
// compatibility forms, which would merge passwords that differ.
func TestHostile_Plaintext_normalizationFoldsCanonicalFormsOnly(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	composed := "Caf\u00e9-Mu\u00f1oz-9"
	decomposed := norm.NFD.String(composed)
	if composed == decomposed {
		t.Fatal("test bug: NFD equals NFC")
	}
	hash, err := m.Hash(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Verify(composed, hash); err != nil || !ok {
		t.Errorf("composed spelling against a hash of the decomposed one = %v, %v", ok, err)
	}

	// U+212B ANGSTROM SIGN decomposes canonically to U+00C5, so it is the same
	// password as the letter.
	angstrom, err := m.Hash("Unit-\u00c5ngstrom-1")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Verify("Unit-\u212bngstrom-1", angstrom); err != nil || !ok {
		t.Errorf("angstrom sign against the letter = %v, %v", ok, err)
	}

	// Distinct under NFC, equal only under NFKC: they must stay distinct.
	for name, pair := range map[string][2]string{
		"fullwidth letters": {"Passw0rd-Strong", "\uff30assw0rd-Strong"},
		"fi ligature":       {"Final-Offer-9!", "\ufb01nal-Offer-9!"},
		"superscript two":   {"Square-Root-2!", "Square-Root-\u00b2!"},
	} {
		h, err := m.Hash(pair[0])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ok, _ := m.Verify(pair[1], h); ok {
			t.Errorf("%s: a compatibility-equivalent password verified", name)
		}
	}
}

// Hash applies the policy and Verify does not, because Verify must accept the
// passwords of accounts created under an older, weaker policy. What Verify
// must still do with a hostile plaintext is return, not panic.
func TestHostile_Plaintext_verifyNeverPanicsOnAnyBytes(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	hash, _ := m.Hash(hostiletest.Strong)
	for name, pw := range map[string]string{
		"empty":         "",
		"NUL":           "\x00",
		"only NULs":     strings.Repeat("\x00", 4096),
		"invalid UTF-8": "\xff\xfe\xfd",
		"one MiB":       strings.Repeat("A", 1<<20),
		"bidi":          "\u202e" + hostiletest.Strong,
	} {
		ok, err := m.Verify(pw, hash)
		if ok || err != nil {
			t.Errorf("%s: Verify = %v, %v; want false, nil", name, ok, err)
		}
	}
}

// Each character class the policy asks for is demanded on its own.
func TestHostile_Plaintext_everyRequiredClassIsEnforced(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	for name, tc := range map[string]struct{ pw, reason string }{
		"no upper":  {"correct-horse-9", "uppercase"},
		"no lower":  {"CORRECT-HORSE-9", "lowercase"},
		"no digit":  {"Correct-Horse-x", "digit"},
		"no symbol": {"CorrectHorse999", "special"},
		// Letters that are neither upper nor lower case do not stand in for
		// either: a title case digraph, a caseless script, a number letter.
		"title case digraph only": {"\u01c5\u01c5\u01c5\u01c5\u01c5\u01c5\u01c5\u01c5\u01c5\u01c5-9a", "uppercase"},
		"caseless script only":    {"\u4e2d\u6587\u5bc6\u7801\u4e2d\u6587\u5bc6\u7801\u4e2d\u6587-9", "uppercase"},
		"too short":               {"Aa1!aaa", "at least"},
		"empty":                   {"", "at least"},
	} {
		err := m.ValidatePolicy(tc.pw)
		if !errors.Is(err, password.ErrWeakPassword) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: ValidatePolicy = %v, want ErrWeakPassword naming %q", name, err, tc.reason)
		}
	}
}

// The policy flags are copied at construction. A caller that keeps the *bool
// it passed in, or another goroutine that flips it afterwards, cannot loosen
// a module that is already serving.
func TestHostile_Plaintext_policyFlagsAreSnapshottedAtConstruction(t *testing.T) {
	cfg := hostiletest.LowCost()
	cfg.RequireUpper, cfg.RequireLower = password.Bool(true), password.Bool(true)
	cfg.RequireDigit, cfg.RequireSymbol = password.Bool(true), password.Bool(true)
	m := hostiletest.NewModule(t, cfg)

	*cfg.RequireUpper, *cfg.RequireLower, *cfg.RequireDigit, *cfg.RequireSymbol = false, false, false, false

	if err := m.ValidatePolicy("alllowercaseonly"); !errors.Is(err, password.ErrWeakPassword) {
		t.Fatalf("a flag flipped after New loosened the policy: %v", err)
	}
}

// Construction refuses settings that would make the hashing weak enough to
// brute force, or heavy enough to take the host down.
func TestHostile_Plaintext_costAndPolicyBoundsAreEnforcedAtConstruction(t *testing.T) {
	for name, cfg := range map[string]password.Config{
		"memory below 8 MiB":    {Memory: 8*1024 - 1},
		"memory above 4 GiB":    {Memory: 4*1024*1024 + 1},
		"memory uint32 max":     {Memory: 1<<32 - 1},
		"iterations above 20":   {Iterations: 21},
		"iterations uint32 max": {Iterations: 1<<32 - 1},
		"min length 7":          {MinLength: 7},
		"min length negative":   {MinLength: -1},
		"max below min":         {MinLength: 20, MaxLength: 19},
		"max length 1025":       {MaxLength: 1025},
		"max length huge":       {MaxLength: 1 << 30},
	} {
		if _, err := password.New(hostiletest.NewProvider(t), cfg); !errors.Is(err, password.ErrInvalidConfig) {
			t.Errorf("%s: password.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := password.New(hostiletest.NewProvider(t), password.Config{Memory: 8 * 1024, Iterations: 20, MinLength: 8, MaxLength: 1024}); err != nil {
		t.Errorf("control: the extremes that are allowed were refused: %v", err)
	}
	if _, err := password.New(hostiletest.NewProvider(t), password.Config{}, password.Config{}); !errors.Is(err, password.ErrInvalidConfig) {
		t.Errorf("two configs: %v, want ErrInvalidConfig", err)
	}
}
