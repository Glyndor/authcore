package email

import (
	"errors"
	"strings"
	"testing"
)

// ---- ValidateAndNormalize() -------------------------------------------------

func TestValidateAndNormalize_normalizes(t *testing.T) {
	m := newMod(t)
	got, err := m.ValidateAndNormalize("  USER@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q, want %q", got, "user@example.com")
	}
}

func TestValidateAndNormalize_idnSubdomainEachLabelConverted(t *testing.T) {
	// When a multi-label IDN domain is supplied, every Unicode label must
	// be converted to its punycode form, not just the rightmost one.
	got, err := newMod(t).ValidateAndNormalize("user@süd.münchen.de")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "user@xn--sd-xka.xn--mnchen-3ya.de"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestValidateAndNormalize_idnWithOverlongLabelRejected(t *testing.T) {
	// idna.Lookup caps a single label at 63 characters. When ToASCII produces
	// a valid ASCII form whose label exceeds that cap, normalize accepts the
	// conversion and the downstream 63-character label rule rejects the
	// address with ErrInvalidEmail.
	overlongLabel := strings.Repeat("ä", 60) // ~120 bytes UTF-8, punycode expands further → >63
	_, err := newMod(t).ValidateAndNormalize("user@" + overlongLabel + ".com")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for overlong IDN label, got %v", err)
	}
}

func TestValidateAndNormalize_idnDomainConvertedToPunycode(t *testing.T) {
	// "münchen.de" is a legitimate German internationalised domain name.
	// Without IDN support the validator rejects it as non-ASCII; with IDN
	// support it is converted to its punycode (xn--mnchen-3ya.de) form that
	// DNS can actually resolve.
	got, err := newMod(t).ValidateAndNormalize("user@münchen.de")
	if err != nil {
		t.Fatalf("unexpected error for IDN email: %v", err)
	}
	want := "user@xn--mnchen-3ya.de"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestValidateAndNormalize_rejectsIDNAFailure covers the regression where a
// domain that IDNA cannot convert (leading-hyphen label, underscore in a
// label, etc.) silently fell through to the raw input and the downstream
// structural checks accepted it. The conversion failure must be propagated
// as ErrInvalidEmail with an empty canonical form: a malformed IDN has no
// canonical form to store or query.
func TestValidateAndNormalize_rejectsIDNAFailure(t *testing.T) {
	m := newMod(t)
	for _, addr := range []string{
		"user@-example.com",   // leading hyphen in a label
		"user@exa_mple.com",   // underscore, forbidden in DNS labels
		"user@example-.com",   // trailing hyphen in a label
		"user@example.com:80", // colon, forbidden in DNS labels
	} {
		got, err := m.ValidateAndNormalize(addr)
		if !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%s: expected ErrInvalidEmail, got %v", addr, err)
		}
		if got != "" {
			t.Errorf("%s: expected empty result on rejection, got %q", addr, got)
		}
	}
}

// Acceptance pair for TestValidateAndNormalize_rejectsIDNAFailure: a domain
// IDNA does convert must still normalise to its punycode form, otherwise
// the rejection path above could pass for any input at all.
func TestValidateAndNormalize_acceptsConvertibleIDN(t *testing.T) {
	got, err := newMod(t).ValidateAndNormalize("user@bücher.example")
	if err != nil {
		t.Fatalf("unexpected error for convertible IDN: %v", err)
	}
	want := "user@xn--bcher-kva.example"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestValidateAndNormalize_invalidReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("not-an-email")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidateAndNormalize_emptyReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

// The local part has one canonical spelling since 2026-09-25: NFC, then
// lowercased. Each refusal below is paired with an address of the same
// shape that is accepted.

// The local part has one canonical spelling since 2026-09-25: NFC, then
// lowercased. Each refusal below is paired with an address of the same
// shape that is accepted.

func TestValidateAndNormalize_localPartHasOneCanonicalForm(t *testing.T) {
	m := newMod(t)
	nfc, err := m.ValidateAndNormalize("José@Example.com")
	if err != nil {
		t.Fatalf("NFC input: %v", err)
	}
	nfd, err := m.ValidateAndNormalize("José@example.com")
	if err != nil {
		t.Fatalf("NFD input: %v", err)
	}
	if nfc != nfd || nfc != "josé@example.com" {
		t.Fatalf("canonical forms differ or are not NFC lowercase: %q vs %q", nfc, nfd)
	}
}

// A non-ASCII letter whose lowercase is ASCII would give two mailboxes one
// canonical form. U+0130 has no canonical decomposition and folds to "i" by
// case mapping alone, so it is refused. U+212A KELVIN SIGN is canonically
// equivalent to K: NFC turns it into the letter before anything else looks,
// the same way it merges a decomposed accent, so it canonicalises to
// "kelly" rather than being refused.
func TestValidateAndNormalize_localPartThatFoldsIntoASCII(t *testing.T) {
	m := newMod(t)
	_, err := m.ValidateAndNormalize("\u0130nfo@example.com")
	if !errors.Is(err, ErrInvalidEmail) || !strings.Contains(err.Error(), "lowercases to an ASCII letter") {
		t.Errorf("capital dotted i: %v, want the fold refusal", err)
	}
	if got, err := m.ValidateAndNormalize("\u212aelly@example.com"); err != nil || got != "kelly@example.com" {
		t.Errorf("kelvin sign: %q, %v; want the canonical kelly@example.com", got, err)
	}
	for _, addr := range []string{"kelly@example.com", "info@example.com", "KELLY@example.com"} {
		if _, err := m.ValidateAndNormalize(addr); err != nil {
			t.Errorf("%s: %v, want accepted", addr, err)
		}
	}
}

func TestValidateAndNormalize_refusesInvisibleAndControlCharactersInTheLocalPart(t *testing.T) {
	m := newMod(t)
	for name, addr := range map[string]string{
		"zero width space":       "admin\u200b@example.com",
		"soft hyphen":            "ad\u00admin@example.com",
		"right-to-left override": "admin\u202e@example.com",
		"next line (C1 control)": "admin\u0085@example.com",
		"line separator":         "admin @example.com",
		"hangul filler":          "adminㅤ@example.com",
	} {
		_, err := m.ValidateAndNormalize(addr)
		if !errors.Is(err, ErrInvalidEmail) || !strings.Contains(err.Error(), "invisible or control character") {
			t.Errorf("%s: %v, want the invisible-character refusal", name, err)
		}
	}
	if got, err := m.ValidateAndNormalize("ad-min.user+tag@example.com"); err != nil || got != "ad-min.user+tag@example.com" {
		t.Fatalf("a plain local part: %q, %v", got, err)
	}
}

// An all-digit top-level label is a bare IPv4 address in another spelling.
func TestValidateAndNormalize_refusesAnAllDigitTopLevelDomain(t *testing.T) {
	m := newMod(t)
	for _, addr := range []string{"user@127.0.0.1", "user@1.2"} {
		if _, err := m.ValidateAndNormalize(addr); !errors.Is(err, ErrInvalidEmail) || !strings.Contains(err.Error(), "top-level domain must not be all digits") {
			t.Errorf("%s: %v, want the all-digit refusal", addr, err)
		}
	}
	for _, addr := range []string{"user@123.example.com", "user@example.co1"} {
		if _, err := m.ValidateAndNormalize(addr); err != nil {
			t.Errorf("%s: %v, want accepted", addr, err)
		}
	}
}
