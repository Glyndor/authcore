package email

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

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
		"zero width space":       "admin​@example.com",
		"soft hyphen":            "ad­min@example.com",
		"right-to-left override": "admin‮@example.com",
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

// An MX answer with no records and no error is a domain without MX, not one
// that accepts mail. The branch could be deleted with the suite green.
func TestVerifyDomain_emptyAnswerIsNoMX(t *testing.T) {
	m := newMod(t)
	stub := newStub([]*net.MX{}, nil)
	m.resolver = stub
	if err := m.VerifyDomain(context.Background(), "user@nomx.example"); !errors.Is(err, ErrDomainNoMX) {
		t.Fatalf("empty answer: %v, want ErrDomainNoMX", err)
	}
	m.resolver = newStub([]*net.MX{{Host: "mx.example.", Pref: 10}}, nil)
	if err := m.VerifyDomain(context.Background(), "user@hasmx.example"); err != nil {
		t.Fatalf("a real record: %v, want nil", err)
	}
}
