package email

import (
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// CONTRACT, not a defect: the local part of an email address is opaque
// (RFC 5321), so the module applies NFC and lowercasing and refuses invisible
// characters but does not fold characters that only look alike. A Cyrillic
// "a" (U+0430) and a Latin "a" give two different, both valid, canonical
// addresses. Only the receiving server knows which spellings reach one
// mailbox, so an application that needs robust uniqueness applies its own
// policy first (ASCII-only local part, no mixed scripts). If this test starts
// failing because the module began folding, that is a behaviour change to
// document in docs/guides/validation.md and release as such, not a quiet fix.
func TestContract_Email_lookAlikeLocalPartsStayDistinct(t *testing.T) {
	m := hostiletest.NewEmail(t)
	latin, err := m.ValidateAndNormalize("alice@example.com")
	if err != nil {
		t.Fatalf("Latin address refused: %v", err)
	}
	for name, in := range map[string]string{
		"Cyrillic a (U+0430)":         "аlice@example.com",
		"Cyrillic e (U+0435)":         "alicе@example.com",
		"Greek omicron for o":         "bοb@example.com",
		"Cyrillic and Latin mixed":    "аlіce@example.com",
		"fullwidth letters (not NFC)": "ａlice@example.com",
	} {
		got, err := m.ValidateAndNormalize(in)
		if err != nil {
			t.Errorf("%s: refused (%v); the contract is that it is accepted", name, err)
			continue
		}
		if got == latin {
			t.Errorf("%s: folded into %q; the contract is that look-alikes stay distinct", name, got)
		}
	}
}

// The domain is the opposite case and is a contract too: a look-alike domain is
// converted to punycode, so it is stored as a name that is not the real one.
func TestContract_Email_lookAlikeDomainBecomesPunycode(t *testing.T) {
	m := hostiletest.NewEmail(t)
	real, err := m.ValidateAndNormalize("alice@apple.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.ValidateAndNormalize("alice@аpple.com")
	if err != nil {
		t.Fatalf("look-alike domain refused: %v", err)
	}
	if got == real || got != "alice@xn--pple-43d.com" {
		t.Errorf("look-alike domain = %q, want the xn-- form distinct from %q", got, real)
	}
}
