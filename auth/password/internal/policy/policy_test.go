package policy

import (
	"errors"
	"strings"
	"testing"
)

var all = Rules{MinLength: 12, MaxLength: 64, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true}

// validBase satisfies the default rules on its own: 13 characters, upper,
// lower, digit and a real symbol.
const validBase = "Abcdefghijk1!"

// noSymbolBase is the password from #347: 12 characters, upper, lower and
// digit, and nothing that counts as special.
const noSymbolBase = "Abcdefghijk1"

func TestCheck_lengthIsMeasuredInRunes(t *testing.T) {
	if err := Check(validBase, all); err != nil {
		t.Fatalf("base must be valid: %v", err)
	}
	if err := Check(strings.Repeat("a", 11), all); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("short = %v, want the minimum-length reason", err)
	}
	if err := Check(strings.Repeat("a", 65), all); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("long = %v, want the maximum-length reason", err)
	}
	// Four CJK characters are four characters, not twelve bytes.
	cjk := Rules{MinLength: 4, MaxLength: 4}
	if err := Check("密码密码", cjk); err != nil {
		t.Fatalf("4 runes under a 4-rune bound: %v", err)
	}
	if err := Check("密码密码密", cjk); err == nil {
		t.Fatal("5 runes under a 4-rune bound was accepted")
	}
}

func TestCheck_requiredClasses(t *testing.T) {
	for name, tc := range map[string]struct {
		pw   string
		want string
	}{
		"no upper":  {"abcdefghijk1!", "uppercase"},
		"no lower":  {"ABCDEFGHIJK1!", "lowercase"},
		"no digit":  {"Abcdefghijkl!", "digit"},
		"no symbol": {noSymbolBase, "special"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check(tc.pw, all); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Check(%q) = %v, want a reason naming %q", tc.pw, err, tc.want)
			}
			if err := Check(tc.pw, Rules{MinLength: 12, MaxLength: 64}); err != nil {
				t.Fatalf("with every class off: %v", err)
			}
		})
	}
}

func TestCheck_refusesNonPrintableWhateverTheRules(t *testing.T) {
	for name, c := range map[string]string{
		"NUL": "\x00", "newline": "\n", "tab": "\t", "DEL": "\x7f", "C1 control": "\u0085",
		"zero width joiner": "\u200d", "no-break space": "\u00a0", "line separator": "\u2028",
		"invalid UTF-8": "\xff", "replacement character": "\ufffd", "braille blank": "\u2800",
		"hangul filler": "\u3164", "combining grapheme joiner": "\u034f", "unassigned": "\U000e0080",
	} {
		t.Run(name, func(t *testing.T) {
			for _, rules := range []Rules{all, {MinLength: 8, MaxLength: 64}} {
				if err := Check(noSymbolBase+c, rules); !errors.Is(err, ErrNonPrintable) {
					t.Fatalf("Check(base+%q) = %v, want ErrNonPrintable", c, err)
				}
			}
		})
	}
}

func TestCheck_specialClassMembers(t *testing.T) {
	for name, c := range map[string]string{
		"space": " ", "ASCII punctuation": "!", "currency symbol": "€", "math symbol": "+", "unicode punctuation": "¿",
	} {
		if err := Check(noSymbolBase+c, all); err != nil {
			t.Errorf("%s: %v, want it to satisfy the symbol class", name, err)
		}
	}
	// A printable rune outside the four classes is allowed and satisfies none.
	if err := Check(noSymbolBase+"字", all); err == nil {
		t.Error("an ideograph satisfied the symbol class")
	}
	if err := Check(noSymbolBase+"字", Rules{MinLength: 12, MaxLength: 64, RequireUpper: true, RequireLower: true, RequireDigit: true}); err != nil {
		t.Errorf("an ideograph must be accepted when no symbol is required: %v", err)
	}
}
