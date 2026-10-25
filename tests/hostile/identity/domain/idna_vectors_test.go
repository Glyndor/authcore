// Package domain attacks the domain half of an email address: IDNA mapping,
// Punycode forms and invalid encodings.
package domain

import (
	"strings"
	"testing"

	"golang.org/x/net/idna"

	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// Domain vectors in the style of the UTS #46 conformance suite (the suite's
// data file is not vendored here, so these are the cases chosen by hand for the
// rules that matter to an address: mapping, deviation characters, joiners, the
// bidi rule, hyphens, separators and invalid punycode). Accepted inputs are
// written out in their ASCII form.
func TestHostile_IDNA_acceptedDomainsHaveTheirASCIIForm(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for name, tc := range map[string]struct{ in, want string }{
		"sharp s kept (non-transitional)":  {"a@faß.de", "a@xn--fa-hia.de"},
		"final sigma kept":                 {"a@ς.com", "a@xn--3xa.com"},
		"sigma and final sigma kept":       {"a@σς.com", "a@xn--3xab.com"},
		"ZWJ after a virama":               {"a@क\u094d\u200dष.com", "a@xn--11b2ezcw70k.com"},
		"ZWNJ after a virama":              {"a@क\u094d\u200cष.com", "a@xn--11b2ezcs70k.com"},
		"right to left label":              {"a@אב.com", "a@xn--4dbc.com"},
		"right to left then digit":         {"a@א1.com", "a@xn--1-zhc.com"},
		"two right to left labels":         {"a@אב.ג.com", "a@xn--4dbc.xn--6db.com"},
		"arabic label":                     {"a@العربية.com", "a@xn--mgbcd4a2b0d2b.com"},
		"ideographic full stop":            {"a@a。b.com", "a@a.b.com"},
		"fullwidth full stop":              {"a@a．b.com", "a@a.b.com"},
		"halfwidth ideographic full stop":  {"a@a｡b.com", "a@a.b.com"},
		"soft hyphen is ignored":           {"a@a\u00adb.com", "a@ab.com"},
		"upper case punycode":              {"a@XN--MNCHEN-3YA.DE", "a@xn--mnchen-3ya.de"},
		"punycode passes through":          {"a@xn--bcher-kva.xn--bcher-kva", "a@xn--bcher-kva.xn--bcher-kva"},
		"precomposed and decomposed agree": {"a@e\u0301.com", "a@xn--9ca.com"},
		"emoji label":                      {"a@\U0001f600.com", "a@xn--e28h.com"},
		"ligature mapped":                  {"a@ﬁ.com", "a@fi.com"},
	} {
		got, err := m.ValidateAndNormalize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q -> %q, %v; want %q", name, tc.in, got, err, tc.want)
		}
	}
}

func TestHostile_IDNA_refusedDomains(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for name, in := range map[string]string{
		"ZWJ with no virama":             "a@a\u200db.com",
		"ZWNJ with no virama":            "a@a\u200cb.com",
		"leading combining mark":         "a@\u0301a.com",
		"bidi: right to left then Latin": "a@אa.com",
		"bidi: digit then right to left": "a@1א.com",
		"arabic-indic digit alone":       "a@٠.com",
		"hyphens in positions 3 and 4":   "a@ab--cd.com",
		"leading hyphen":                 "a@-ab.com",
		"trailing hyphen label":          "a@a.b-.com",
		"invalid punycode, short":        "a@xn--a.com",
		"invalid punycode, two chars":    "a@xn--ab.com",
		"empty punycode":                 "a@xn--.com",
		"underscore":                     "a@a_b.com",
		"space":                          "a@a b.com",
		"colon":                          "a@a:b.com",
		"slash":                          "a@a/b.com",
		"percent escape":                 "a@a%41.com",
		"second at sign":                 "a@a@b.com",
		"one dot leader":                 "a@a․b.com",
		"enclosed digit with full stop":  "a@⒈.com",
		"trailing dot":                   "a@example.com.",
		"trailing dot, punycode":         "a@xn--mnchen-3ya.de.",
		"empty label":                    "a@a..b.com",
		"leading dot":                    "a@.a.com",
		"single label":                   "a@com",
		"single IDN label":               "a@日本",
		"only a fullwidth dot":           "a@．.com",
	} {
		if got, err := m.ValidateAndNormalize(in); err == nil {
			t.Errorf("%s: %q was accepted as %q", name, in, got)
		}
	}
}

// A Unicode label grows when it becomes punycode, and the limits of DNS apply to
// the grown form. The longest label that fits is accepted and one character
// more is not, and nothing that survives is over the limit in total.
func TestHostile_IDNA_limitsApplyToThePunycodeForm(t *testing.T) {
	m := hostiletest.NewEmail(t)
	fits := func(n int) bool {
		a, err := idna.Lookup.ToASCII(strings.Repeat("ü", n))
		return err == nil && len(a) <= 63
	}
	longest := 0
	for fits(longest + 1) {
		longest++
	}
	if longest < 10 || longest > 62 {
		t.Fatalf("test bug: %d ü fit in a label", longest)
	}
	if got, err := m.ValidateAndNormalize("a@" + strings.Repeat("ü", longest) + ".com"); err != nil {
		t.Errorf("%d characters (63 bytes of punycode): %v, got %q", longest, err, got)
	}
	if got, err := m.ValidateAndNormalize("a@" + strings.Repeat("ü", longest+1) + ".com"); err == nil {
		t.Errorf("%d characters (over 63 bytes of punycode) was accepted as %q", longest+1, got)
	}
	// Short as typed, long once converted: thirty-two one-character labels are
	// 133 bytes of input and 261 bytes of ASCII.
	long := "a@" + strings.Repeat("日.", 32) + "com"
	if len(long) > 254 {
		t.Fatalf("test bug: the input is %d bytes", len(long))
	}
	if got, err := m.ValidateAndNormalize(long); err == nil {
		t.Errorf("an address of %d bytes after conversion was accepted: %q", len(got), got)
	}
}
