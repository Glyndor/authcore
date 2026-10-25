package identity_test

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// FuzzEmailCanonicalFixedPoint requires of every address the module accepts
// that its output is a fixed point (normalising it again changes nothing), that
// the ASCII case of the input and the Unicode form of the input do not change
// the verdict or the result, and that the output obeys the limits of the
// format and carries no character that could hide or reorder text.
func FuzzEmailCanonicalFixedPoint(f *testing.F) {
	m := newEmail(f)
	for _, s := range []string{
		"alice@example.com", "Alice@Example.COM", "a@xn--mnchen-3ya.de", "e\u0301lise@münchen.de", "ÉLISE@EXAMPLE.COM",
		"a+b@example.co.uk", "a@İ.com", "a@faß.de", "Kevin@example.com", "a@אב.com", "x@日本.jp",
		"a@a。b.com", "\"quoted\"@example.com", "a@[127.0.0.1]", "  a@b.cc  ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := m.ValidateAndNormalize(s)
		if err != nil {
			return
		}
		again, err := m.ValidateAndNormalize(got)
		if err != nil || again != got {
			t.Fatalf("%q -> %q, and again -> %q, %v", s, got, again, err)
		}
		assertCanonicalLimits(t, s, got)
		// Other spellings of the same input.
		upper := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r - 32
			}
			return r
		}, s)
		if other, err := m.ValidateAndNormalize(upper); err != nil || other != got {
			t.Fatalf("ASCII upper case of %q gave %q, %v; want %q", s, other, err, got)
		}
		if other, err := m.ValidateAndNormalize(norm.NFD.String(s)); err != nil || other != got {
			t.Fatalf("NFD of %q gave %q, %v; want %q", s, other, err, got)
		}
	})
}

// assertCanonicalLimits fails the test when an accepted address, got, breaks
// the limits of the format or keeps a character that hides or reorders text.
func assertCanonicalLimits(t *testing.T, input, got string) {
	t.Helper()
	at := strings.LastIndexByte(got, '@')
	local, domain := got[:at], got[at+1:]
	if len(got) > 254 || len(local) > 64 || len(local) == 0 {
		t.Fatalf("%q -> %q breaks the length limits", input, got)
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			t.Fatalf("%q -> %q has a label of %d bytes", input, got, len(label))
		}
	}
	for _, r := range domain {
		if r > unicode.MaxASCII {
			t.Fatalf("%q -> %q: the domain is not ASCII", input, got)
		}
	}
	for _, r := range local {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError {
			t.Fatalf("%q -> %q keeps U+%04X", input, got, r)
		}
	}
}

var usernameShape = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$`)

// FuzzUsernameMatchesSpec compares the username module with its specification
// written as a regular expression: after trimming and lower-casing, 3 to 32
// characters of [a-z0-9_-], alphanumeric at both ends, no two specials in a
// row. Whatever matches is accepted unless the name is reserved, and nothing
// else is accepted.
func FuzzUsernameMatchesSpec(f *testing.F) {
	m := newUsername(f)
	for _, s := range []string{"alice", "Alice_99", " bob-smith ", "a--b", "-a-", "ab", strings.Repeat("a", 33), "admin", "ROOT", "Kevin", "İstanbul", "café", "x_y-z", "a.b", "a b", "ab_", "a-_b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		want := strings.ToLower(strings.TrimSpace(s))
		shaped := len(want) >= 3 && len(want) <= 32 && usernameShape.MatchString(want) &&
			!strings.Contains(want, "__") && !strings.Contains(want, "--") && !strings.Contains(want, "_-") && !strings.Contains(want, "-_")
		got, err := m.ValidateAndNormalize(s)
		switch {
		case err == nil && !shaped:
			t.Fatalf("%q was accepted as %q, which is outside the specification", s, got)
		case err == nil && got != want:
			t.Fatalf("%q normalised to %q, want %q", s, got, want)
		case err != nil && shaped && !strings.Contains(err.Error(), "reserved"):
			t.Fatalf("%q (%q) matches the specification but was refused: %v", s, want, err)
		}
	})
}
