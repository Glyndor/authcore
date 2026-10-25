package identity_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/username"
)

// defaultReserved is the set of names an operator expects nobody to register
// without asking. The test keeps its own copy on purpose: if a name is dropped
// from the module's list, this copy is what notices.
var defaultReserved = []string{
	"admin", "administrator", "root", "superuser", "system",
	"api", "auth", "oauth", "webhook", "service", "daemon", "bot",
	"www", "ftp", "smtp", "pop", "imap", "mail", "email",
	"anonymous", "guest", "user", "self",
	"login", "logout", "register", "signup", "signin", "signout",
	"settings", "profile", "account", "dashboard", "home",
	"null", "undefined", "none", "true", "false",
	"test", "dev", "prod", "staging", "support", "help", "info",
}

func mustBeReserved(t *testing.T, err error, input string) {
	t.Helper()
	if !errors.Is(err, username.ErrInvalidUsername) || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("%q: %v, want ErrInvalidUsername naming a reserved name", input, err)
	}
}

// Every reserved name is refused in every spelling that normalises to it:
// case, outer whitespace of every kind, and the characters whose lower case is
// the ASCII letter. A name that merely contains an invisible or foreign
// character is refused by the character set instead.
func TestHostile_Username_reservedNamesCannotBeSpelledAround(t *testing.T) {
	m := newUsername(t)
	for _, name := range defaultReserved {
		for _, in := range []string{
			name, strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:], "  " + name, name + "  ", "\t" + name + "\n",
			"\u00a0" + name, name + "\u00a0", "\u2003" + name, "\u3000" + name + "\u3000", "\u0085" + name, name + "\r\n",
		} {
			got, err := m.ValidateAndNormalize(in)
			if got != "" {
				t.Errorf("%q was accepted as %q", in, got)
			}
			mustBeReserved(t, err, in)
		}
	}
	// Upper case that is not ASCII but lowers to an ASCII letter.
	for in := range map[string]bool{"ADM\u0130N": true, "\u0130NFO": true, "\u0130nfo": true} {
		got, err := m.ValidateAndNormalize(in)
		if got != "" {
			t.Errorf("%q was accepted as %q", in, got)
		}
		mustBeReserved(t, err, in)
	}
}

// Evasions that hide a reserved name in characters the set does not allow are
// refused as invalid, whichever way they are hidden.
func TestHostile_Username_invisibleAndLookalikeCharactersAreRefused(t *testing.T) {
	m := newUsername(t)
	for name, in := range map[string]string{
		"zero width space":           "ad\u200bmin",
		"zero width joiner":          "ad\u200dmin",
		"zero width non-joiner":      "ad\u200cmin",
		"word joiner":                "ad\u2060min",
		"byte order mark":            "\ufeffadmin",
		"soft hyphen":                "ad\u00admin",
		"bidi override":              "\u202eadmin",
		"bidi isolate":               "ad\u2066min",
		"left-to-right mark":         "ad\u200emin",
		"combining acute":            "adm\u0301in",
		"combining dot above":        "a\u0307dmin",
		"variation selector":         "adm\ufe0fin",
		"hangul filler":              "ad\u3164min",
		"braille blank":              "ad\u2800min",
		"cyrillic a":                 "\u0430dmin",
		"cyrillic a inside":          "adm\u0456n",
		"cyrillic o":                 "r\u043e\u043et",
		"greek omicron":              "r\u03bf\u03bft",
		"dotless i":                  "\u0131nfo",
		"dotless i inside":           "supp\u043ert",
		"long s":                     "\u017fystem",
		"long s inside":              "sy\u017ftem",
		"fullwidth letter":           "\uff41dmin",
		"fullwidth hyphen":           "ad\uff0dmin",
		"fullwidth underscore":       "ad\uff3fmin",
		"mathematical bold a":        "\U0001d41adm\U0001d422n",
		"circled a":                  "\u24d0dmin",
		"superscript letter":         "\u1d43dmin",
		"ligature fi":                "\ufb01nal",
		"roman numeral":              "\u2160\u2160\u2160",
		"leading underscore":         "_alice",
		"leading hyphen":             "-alice",
		"trailing underscore":        "alice_",
		"trailing hyphen":            "alice-",
		"inner space":                "ad min",
		"inner tab":                  "ad\tmin",
		"inner newline":              "ad\nmin",
		"inner NUL":                  "ad\x00min",
		"trailing NUL":               "admin\x00",
		"dot":                        "ad.min",
		"at sign":                    "admin@host",
		"slash":                      "ad/min",
		"backslash":                  "ad\\min",
		"percent":                    "ad%6din",
		"colon":                      "ad:min",
		"quote":                      "ad'min",
		"angle":                      "<admin>",
		"plus":                       "admin+x",
		"emoji":                      "adm\U0001f600n",
		"invalid UTF-8":              "ad\xffmin",
		"combined hyphen/underscore": "ad-_min",
		"double hyphen":              "ad--min",
		"double underscore":          "ad__min",
	} {
		got, err := m.ValidateAndNormalize(in)
		if got != "" || !errors.Is(err, username.ErrInvalidUsername) {
			t.Errorf("%s (%q): %q, %v; want empty and ErrInvalidUsername", name, in, got, err)
		}
	}
}

// Exhaustive over every Unicode scalar: the only non-ASCII characters that can
// appear in an accepted name are the two whose lower case is an ASCII letter,
// and they leave as that letter. Every accepted name, for every character,
// is made only of [a-z0-9_-]. If a Unicode update adds a third character with
// that property this test names it.
func TestHostile_Username_everyScalarEitherFailsOrFoldsToASCII(t *testing.T) {
	m := newUsername(t)
	folded := map[rune]string{}
	for r := rune(0); r <= 0x10ffff; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		in := "ab" + string(r) + "cd"
		got, err := m.ValidateAndNormalize(in)
		if err != nil {
			continue
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
				t.Fatalf("U+%04X was accepted and left %q in the name", r, got)
			}
		}
		if r > 0x7f {
			folded[r] = got
		}
		if len(got) != 5 {
			t.Fatalf("U+%04X: %q -> %q is not five bytes", r, in, got)
		}
	}
	want := map[rune]string{0x0130: "abicd", 0x212a: "abkcd"}
	if len(folded) != len(want) {
		t.Fatalf("non-ASCII characters accepted: %q, want exactly %q", folded, want)
	}
	for r, g := range want {
		if folded[r] != g {
			t.Errorf("U+%04X folded to %q, want %q", r, folded[r], g)
		}
	}
}

// Every ASCII byte in the middle of a name: letters and digits (either case),
// underscore and hyphen are accepted and the rest, including every control
// byte, are not.
func TestHostile_Username_everyASCIIByteIsClassified(t *testing.T) {
	m := newUsername(t)
	for c := 0; c < 128; c++ {
		in := "ab" + string(rune(c)) + "cd"
		got, err := m.ValidateAndNormalize(in)
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
		if ok && (err != nil || got != strings.ToLower(in)) {
			t.Errorf("byte %#x: %q, %v; want %q", c, got, err, strings.ToLower(in))
		}
		if !ok && (got != "" || !errors.Is(err, username.ErrInvalidUsername)) {
			t.Errorf("byte %#x: %q, %v; want a refusal", c, got, err)
		}
	}
}

// Length bounds are exact, in bytes, on the canonical form, and a huge input is
// refused without cost.
func TestHostile_Username_lengthBoundsAreExact(t *testing.T) {
	m := newUsername(t)
	for n, ok := range map[int]bool{0: false, 1: false, 2: false, 3: true, 32: true, 33: false, 255: false} {
		got, err := m.ValidateAndNormalize(strings.Repeat("a", n))
		if (err == nil) != ok {
			t.Errorf("%d characters: %q, %v; want accepted=%v", n, got, err, ok)
		}
	}
	for _, size := range []int{1 << 20, 16 << 20} {
		start := time.Now()
		if got, err := m.ValidateAndNormalize(strings.Repeat("a", size)); got != "" || !errors.Is(err, username.ErrInvalidUsername) {
			t.Errorf("%d bytes: %q, %v", size, got[:min(10, len(got))], err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%d bytes took %v", size, d)
		}
	}
	if _, err := m.ValidateAndNormalize(strings.Repeat(" ", 1<<20) + "alice" + strings.Repeat(" ", 1<<20)); err != nil {
		t.Errorf("outer whitespace of any length is trimmed: %v", err)
	}
}

// Operator policy is normalised the same way input is, and cannot be defeated by
// the spelling of the input.
func TestHostile_Username_operatorReservedListsAreNormalised(t *testing.T) {
	m := newUsername(t, username.Config{
		ExtraReservedNames: []string{"  Billing ", "SALES", "", "   "},
		AllowReservedNames: []string{" ADMIN"},
	})
	for _, in := range []string{"billing", "BILLING", " Billing\t", "sales", "Sales"} {
		_, err := m.ValidateAndNormalize(in)
		mustBeReserved(t, err, in)
	}
	if got, err := m.ValidateAndNormalize("Admin"); err != nil || got != "admin" {
		t.Errorf("an allowed name: %q, %v", got, err)
	}
	if _, err := m.ValidateAndNormalize("root"); err == nil {
		t.Error("allowing one name released another")
	}
}

// Configuration bounds.
func TestHostile_Username_configurationBounds(t *testing.T) {
	for name, cfg := range map[string]username.Config{
		"min negative":  {MinLength: -1},
		"max below min": {MinLength: 10, MaxLength: 9},
		"max 256":       {MaxLength: 256},
		"max huge":      {MaxLength: 1 << 30},
	} {
		if _, err := username.NewWithConfig(newProvider(t), cfg); !errors.Is(err, username.ErrInvalidConfig) {
			t.Errorf("%s: %v, want ErrInvalidConfig", name, err)
		}
	}
	m, err := username.NewWithConfig(newProvider(t), username.Config{MinLength: 1, MaxLength: 255})
	if err != nil {
		t.Fatalf("control: the widest bounds were refused: %v", err)
	}
	if _, err := m.ValidateAndNormalize("a"); err != nil {
		t.Errorf("one character under min 1: %v", err)
	}
	if _, err := m.ValidateAndNormalize(strings.Repeat("a", 255)); err != nil {
		t.Errorf("255 characters under max 255: %v", err)
	}
	if _, err := username.New(nil); !errors.Is(err, username.ErrInvalidConfig) {
		t.Errorf("nil provider: %v", err)
	}
}
