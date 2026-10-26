package localpart_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/localpart"
)

// The local part has one canonical spelling since 2026-09-25: NFC, then
// lowercased. Each refusal below is paired with an input of the same shape
// that is accepted.

func TestCanonical_hasOneSpellingForPrecomposedAndDecomposedAccents(t *testing.T) {
	nfc, err := localpart.Canonical("Jos\u00e9")
	if err != nil {
		t.Fatalf("NFC input: %v", err)
	}
	nfd, err := localpart.Canonical("Jose\u0301")
	if err != nil {
		t.Fatalf("NFD input: %v", err)
	}
	if nfc != nfd || nfc != "jos\u00e9" {
		t.Fatalf("canonical forms differ or are not NFC lowercase: %q vs %q", nfc, nfd)
	}
}

// U+0130 folds to "i" by case mapping alone, so it is refused; U+212A KELVIN
// SIGN is canonically equivalent to K, so NFC turns it into the letter.
func TestCanonical_foldingIntoASCII(t *testing.T) {
	_, err := localpart.Canonical("\u0130nfo")
	if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "lowercases to an ASCII letter") {
		t.Errorf("capital dotted i: %v, want the fold refusal", err)
	}
	if got, err := localpart.Canonical("\u212aelly"); err != nil || got != "kelly" {
		t.Errorf("kelvin sign: %q, %v; want kelly", got, err)
	}
	for _, in := range []string{"kelly", "info", "KELLY"} {
		if _, err := localpart.Canonical(in); err != nil {
			t.Errorf("%s: %v, want accepted", in, err)
		}
	}
}

func TestCanonical_refusesInvisibleAndControlCharacters(t *testing.T) {
	for name, in := range map[string]string{
		"zero width space":       "admin\u200b",
		"soft hyphen":            "ad\u00admin",
		"right-to-left override": "admin\u202e",
		"next line (C1 control)": "admin\u0085",
		"line separator":         "admin\u2028",
		"paragraph separator":    "admin\u2029",
		"hangul filler":          "adminㅤ",
	} {
		_, err := localpart.Canonical(in)
		if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "invisible or control character") {
			t.Errorf("%s: %v, want the invisible-character refusal", name, err)
		}
	}
	if got, err := localpart.Canonical("Ad-Min.User+Tag"); err != nil || got != "ad-min.user+tag" {
		t.Fatalf("a plain local part: %q, %v", got, err)
	}
}

func TestCanonical_refusesBytesThatAreNotUTF8(t *testing.T) {
	for _, in := range []string{"al\xffice", "al\xfeice", "\xff", "alice\xc3"} {
		_, err := localpart.Canonical(in)
		if !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("%q: %v, want ErrInvalidEmail", in, err)
		}
	}
	if got, err := localpart.Canonical("al\u00efce"); err != nil || got != "al\u00efce" {
		t.Errorf("valid multibyte: %q, %v", got, err)
	}
}

// Canonical returns a fixed point: running it on its own output changes
// nothing. A capital letter followed by combining marks composes only after
// it is lowercased, so a single NFC pass before lowercasing left two
// spellings for one mailbox.
func TestCanonical_isAFixedPoint(t *testing.T) {
	for name, in := range map[string]string{
		"capital with two combining marks": "T\u0308\u0301",
		"precomposed accent":               "Jos\u00e9",
		"decomposed accent":                "Jose\u0301",
		"plain":                            "User.Name",
	} {
		first, err := localpart.Canonical(in)
		if err != nil {
			t.Errorf("%s: %v, want accepted", name, err)
			continue
		}
		second, err := localpart.Canonical(first)
		if err != nil || second != first {
			t.Errorf("%s: %+q then %+q (%v), want the same spelling", name, first, second, err)
		}
	}
}

func TestCanonical_refusesSpaceSeparators(t *testing.T) {
	for name, in := range map[string]string{
		"thin space":            "ab\u2009cd",
		"no-break space":        "ab\u00a0cd",
		"ideographic space":     "ab\u3000cd",
		"narrow no-break space": "ab\u202fcd",
	} {
		_, err := localpart.Canonical(in)
		if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "invisible or control character") {
			t.Errorf("%s: %v, want the invisible-character refusal", name, err)
		}
	}
}
