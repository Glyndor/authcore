package domain

import (
	"testing"
	"unicode/utf8"

	"golang.org/x/net/idna"

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
		if got, err := m.ValidateAndNormalize("a@" + string(r) + "x.com"); err == nil {
			t.Errorf("U+%04X was accepted as %q; UTS #46 disallows it", r, got)
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
		domain := string(r) + "x.com"
		want, refErr := idna.Lookup.ToASCII(domain)
		got, err := m.ValidateAndNormalize("a@" + domain)
		if (err == nil) != (refErr == nil) {
			t.Errorf("U+%04X: module err = %v, UTS #46 err = %v", r, err, refErr)
			continue
		}
		if err == nil && got != "a@"+want {
			t.Errorf("U+%04X: module %q, UTS #46 %q", r, got, "a@"+want)
		}
	}
}
