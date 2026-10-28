package domain

import (
	"errors"
	"testing"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// The domain is mapped by UTS #46 and by nothing else. A character the standard
// maps one way must not be folded another way first: U+0130 (capital I with dot
// above) is not the ASCII letter "i", and the capital Georgian letters and
// U+04C0 are not valid input that happens to lower-case to something valid.
func TestHostile_Email_domainMappingIsTheStandardsNotGosLowerCase(t *testing.T) {
	m := hostiletest.NewEmail(t)

	got, err := m.ValidateAndNormalize("a@İx.com")
	if err != nil || got != "a@xn--ix-rub.com" {
		t.Errorf("U+0130: %q, %v; want a@xn--ix-rub.com", got, err)
	}
	if plain, _ := m.ValidateAndNormalize("a@ix.com"); got == plain {
		t.Errorf("U+0130 folded onto the ASCII domain %q", plain)
	}
	for _, r := range []rune{0x10a0, 0x10b5, 0x10c5, 0x04c0} {
		if got, err := m.ValidateAndNormalize("a@" + string(r) + "x.com"); !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("U+%04X = %q, %v; UTS #46 disallows it, want ErrInvalidEmail", r, got, err)
		}
	}
}

// Over the whole Basic Multilingual Plane, every single-character domain gets
// from the module exactly the verdict and the ASCII form that UTS #46 gives it
// (here via golang.org/x/net/idna, called directly on the character as typed).
// The module adds only its own structural checks, which these domains meet.
func TestHostile_Email_everyBMPDomainCharacterAgreesWithUTS46(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for r := rune(0x80); r <= 0xffff; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		if r == 0x3002 || r == 0xff0e || r == 0xff61 {
			continue // label separators: a leading one is an empty label, which the structural check refuses
		}
		if r >= 0x2135 && r <= 0x2138 {
			continue // map to Hebrew letters; their ASCII form is refused on a second pass, so the module refuses them (below)
		}
		domain := string(r) + "x.com"
		want, refErr := idna.Lookup.ToASCII(domain)
		got, err := m.ValidateAndNormalize("a@" + domain)
		if (err == nil) != (refErr == nil) {
			t.Errorf("U+%04X: module err = %v, UTS #46 err = %v", r, err, refErr)
			continue
		}
		if err != nil && !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("U+%04X: refused with %v, want ErrInvalidEmail", r, err)
		}
		if err == nil && got != "a@"+want {
			t.Errorf("U+%04X: module %q, UTS #46 %q", r, got, "a@"+want)
		}
	}
}

// Four symbols map to Hebrew letters under UTS #46, and the ASCII name that
// results is refused when it goes through IDNA again. Accepting them stored a
// value the next normalisation rejected, so the module refuses the symbols.
func TestHostile_Email_domainWhoseASCIIFormIsRefusedOnASecondPassIsRefused(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for r := rune(0x2135); r <= 0x2138; r++ {
		if got, err := m.ValidateAndNormalize("a@" + string(r) + "x.com"); !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("U+%04X = %q, %v; want ErrInvalidEmail", r, got, err)
		}
	}
}
