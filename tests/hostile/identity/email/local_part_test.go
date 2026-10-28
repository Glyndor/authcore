package email

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// The local part limit is 64 bytes of the canonical form: after NFC and after
// lower-casing, the two steps that change a length. A part that is short as
// typed but long once canonical must be refused, and one that is long as typed
// but short once canonical must be accepted, or the stored value could exceed
// what the limit promises.
func TestHostile_EmailLocal_limitIsBytesOfTheCanonicalForm(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for name, tc := range map[string]struct {
		local string
		ok    bool
	}{
		"32 two-byte letters (64 bytes)":             {strings.Repeat("é", 32), true},
		"33 two-byte letters (66 bytes)":             {strings.Repeat("é", 33), false},
		"21 chars that grow by one byte lower-cased": {strings.Repeat("Ⱥ", 21), true},  // 42 bytes typed, 63 canonical
		"22 chars that grow by one byte lower-cased": {strings.Repeat("Ⱥ", 22), false}, // 44 bytes typed, 66 canonical
		"32 chars that shrink when lower-cased":      {strings.Repeat("Ɐ", 32), true},  // 96 bytes typed, 64 canonical
		"33 chars that shrink when lower-cased":      {strings.Repeat("Ɐ", 33), false}, // 99 bytes typed, 66 canonical
		"32 decomposed pairs (96 typed, 64 NFC)":     {strings.Repeat("e\u0301", 32), true},
		"33 decomposed pairs (99 typed, 66 NFC)":     {strings.Repeat("e\u0301", 33), false},
		"64 ASCII":                                   {strings.Repeat("a", 64), true},
		"65 ASCII":                                   {strings.Repeat("a", 65), false},
	} {
		got, err := m.ValidateAndNormalize(tc.local + "@example.com")
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v (accepted as %q), want accepted = %v", name, err, got, tc.ok)
			continue
		}
		if !tc.ok && !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("%s: refused with %v, want ErrInvalidEmail", name, err)
		}
		if err == nil {
			if local := got[:strings.LastIndexByte(got, '@')]; len(local) > 64 {
				t.Errorf("%s: stored local part is %d bytes", name, len(local))
			}
		}
	}
}

// Exhaustive over every Unicode scalar: a character that renders as nothing or
// controls the text (control, format, line and paragraph separators, and the
// default-ignorable code points) never survives in an accepted local part, so
// an address cannot hide characters or reorder what a reader sees.
func TestHostile_EmailLocal_noInvisibleOrDirectionalScalarSurvives(t *testing.T) {
	m := hostiletest.NewEmail(t)
	hidden := func(r rune) bool {
		return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
	}
	var survivors []string
	for r := rune(0); r <= 0x10ffff; r++ {
		if !utf8.ValidRune(r) || !hidden(r) {
			continue
		}
		got, err := m.ValidateAndNormalize("a" + string(r) + "b@example.com")
		if err == nil {
			survivors = append(survivors, got)
			if len(survivors) > 5 {
				break
			}
		}
	}
	if len(survivors) > 0 {
		t.Fatalf("invisible or directional characters survived, e.g. %q", survivors)
	}
}

// Combining marks are real text and are kept (NFC decides what composes), but
// they must not be a way round the length limit or turn a letter into another
// one: the canonical form of a base with many marks is bounded by the same 64
// bytes and is stable.
func TestHostile_EmailLocal_combiningMarksAreBoundedAndStable(t *testing.T) {
	m := hostiletest.NewEmail(t)
	zalgo := "a" + strings.Repeat("\u0301\u0323", 15) // 1 + 60 bytes
	got, err := m.ValidateAndNormalize(zalgo + "@example.com")
	if err != nil {
		t.Fatalf("a base with 30 marks within the limit: %v", err)
	}
	again, err := m.ValidateAndNormalize(got)
	if err != nil || again != got {
		t.Errorf("not stable: %q then %q, %v", got, again, err)
	}
	if _, err := m.ValidateAndNormalize("a" + strings.Repeat("\u0301\u0323", 40) + "@example.com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("a base with 80 marks (161 bytes) = %v, want ErrInvalidEmail", err)
	}
	// Marks in either order are one canonical sequence.
	x, _ := m.ValidateAndNormalize("a\u0323\u0302@example.com")
	y, _ := m.ValidateAndNormalize("a\u0302\u0323@example.com")
	if x == "" || x != y {
		t.Errorf("the two orders of two marks gave %q and %q", x, y)
	}
}
