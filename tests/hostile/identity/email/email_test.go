// Package email attacks email canonicalisation: structural attacks, local part
// limits, look-alikes and agreement with the specification.
package email

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// An address is a local part, one at sign and a dotted domain. Every other
// structure that mail parsers know (display names, comments, quoted local parts,
// groups, literals) and every structural defect is refused with ErrInvalidEmail.
func TestHostile_Email_structuralAttacksAreRefused(t *testing.T) {
	m := hostiletest.NewEmail(t)
	if got, err := m.ValidateAndNormalize("alice@example.com"); err != nil || got != "alice@example.com" {
		t.Fatalf("control: %q, %v", got, err)
	}
	cases := map[string]string{
		"empty":                     "",
		"spaces only":               "   ",
		"at only":                   "@",
		"no domain":                 "a@",
		"no local":                  "@b.com",
		"no at":                     "alice.example.com",
		"single label domain":       "a@localhost",
		"trailing dot":              "a@example.com.",
		"leading dot":               "a@.example.com",
		"double dot":                "a@example..com",
		"two at signs":              "a@@example.com",
		"at in local":               "a@b@example.com",
		"space in local":            "a b@example.com",
		"space in domain":           "a@exa mple.com",
		"newline in local":          "a\n@example.com",
		"newline in domain":         "a@exa\nmple.com",
		"tab in local":              "a\t@example.com",
		"NUL in local":              "a\x00@example.com",
		"NUL in domain":             "a@example\x00.com",
		"trailing NUL":              "a@example.com\x00",
		"leading dot local":         ".a@example.com",
		"trailing dot local":        "a.@example.com",
		"double dot local":          "a..b@example.com",
		"quoted local":              `"alice"@example.com`,
		"quoted with space":         `"a b"@example.com`,
		"quoted with at":            `"a@b"@example.com`,
		"comment local":             "alice(comment)@example.com",
		"comment after":             "alice@example.com (comment)",
		"display name":              "Alice <alice@example.com>",
		"angle brackets":            "<alice@example.com>",
		"route":                     "<@relay.example:alice@example.com>",
		"group":                     "friends: alice@example.com;",
		"two addresses":             "a@example.com, b@example.com",
		"two addresses semicolon":   "a@example.com; b@example.com",
		"ipv4 literal":              "a@[127.0.0.1]",
		"ipv6 literal":              "a@[IPv6:::1]",
		"bare ipv4":                 "a@127.0.0.1",
		"all-digit tld":             "a@example.123",
		"underscore in domain":      "a@exa_mple.com",
		"hyphen starts label":       "a@-example.com",
		"hyphen ends label":         "a@example-.com",
		"hyphens in 3rd, 4th":       "a@ex--ample.com",
		"bad punycode":              "a@xn--a.com",
		"bad punycode 2":            "a@xn--.com",
		"zero width joiner":         "a@exa\u200dmple.com",
		"bidi override in domain":   "a@exa\u202emple.com",
		"disallowed in domain":      "a@exa\u2024mple.com",
		"percent in domain":         "a@exa%6dple.com",
		"slash in domain":           "a@example.com/path",
		"colon in domain":           "a@example.com:25",
		"question in domain":        "a@example.com?x=1",
		"hash in domain":            "a@example.com#x",
		"user info in domain":       "a@user:pw@example.com",
		"soft hyphen as label":      "a@\u00ad.com",
		"local of 65":               strings.Repeat("a", 65) + "@example.com",
		"label of 64":               "a@" + strings.Repeat("a", 64) + ".com",
		"total of 255":              addrOfLength(255),
		"four MiB":                  strings.Repeat("a", 4<<20) + "@example.com",
		"zero width space local":    "al\u200bice@example.com",
		"zero width joiner local":   "al\u200dice@example.com",
		"word joiner local":         "al\u2060ice@example.com",
		"byte order mark local":     "\ufeffalice@example.com",
		"soft hyphen local":         "al\u00adice@example.com",
		"bidi override local":       "alice\u202e@example.com",
		"bidi isolate local":        "al\u2066ice@example.com",
		"left-to-right mark":        "al\u200eice@example.com",
		"line separator local":      "al\u2028ice@example.com",
		"paragraph sep local":       "al\u2029ice@example.com",
		"next line local":           "al\u0085ice@example.com",
		"C0 control local":          "al\x01ice@example.com",
		"delete local":              "al\x7fice@example.com",
		"C1 control local":          "al\u009fice@example.com",
		"hangul filler local":       "al\u3164ice@example.com",
		"dotted capital I local":    "\u0130@example.com",
		"combining grapheme joiner": "al\u034fice@example.com",
		"tag character local":       "al\U000e0041ice@example.com",
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			got, err := m.ValidateAndNormalize(addr)
			if got != "" || !errors.Is(err, email.ErrInvalidEmail) {
				t.Fatalf("ValidateAndNormalize = %q, %v; want empty and ErrInvalidEmail", got, err)
			}
			// A guard against a refusal that scales with the input, not a
			// measure of speed: the four MiB case took 0.08 s on Linux and
			// 3.2 s on a loaded macOS runner, which failed a 3 s bound.
			if d := time.Since(start); d > 30*time.Second {
				t.Fatalf("refusing took %v", d)
			}
		})
	}
}

// addrOfLength builds a legal-looking address of exactly n bytes: a 64 byte
// local part and a domain of 63 byte labels.
func addrOfLength(n int) string {
	domain := n - 65
	var labels []string
	for domain > 0 {
		l := min(63, domain)
		if domain-l == 1 { // never leave a one byte remainder that would be a bare dot
			l--
		}
		labels = append(labels, strings.Repeat("a", l))
		domain -= l + 1
	}
	return strings.Repeat("a", 64) + "@" + strings.Join(labels, ".")
}

// Limits are exact: the longest legal address is accepted, one more byte is
// not.
func TestHostile_Email_lengthLimitsAreExact(t *testing.T) {
	m := hostiletest.NewEmail(t)
	label := strings.Repeat("a", 63)
	for name, addr := range map[string]string{
		"local of 64":  strings.Repeat("a", 64) + "@example.com",
		"label of 63":  "a@" + label + ".com",
		"total of 254": addrOfLength(254),
	} {
		if _, err := m.ValidateAndNormalize(addr); err != nil {
			t.Errorf("%s (%d bytes): %v", name, len(addr), err)
		}
	}
	if got := addrOfLength(254); len(got) != 254 {
		t.Fatalf("test bug: fixture is %d bytes", len(got))
	}
}

// Every spelling of one address reduces to one canonical string, so a table
// keyed on it holds one account per mailbox: case, outer whitespace, composed
// versus decomposed accents, compatibility forms in the domain, the ideographic
// full stop and an invisible soft hyphen in the domain all fold.
func TestHostile_Email_spellingsOfOneAddressFoldToOneCanonicalForm(t *testing.T) {
	m := hostiletest.NewEmail(t)
	groups := map[string][]string{
		"alice@example.com": {
			"alice@example.com", "Alice@Example.COM", "ALICE@EXAMPLE.COM", "  alice@example.com  ", "\talice@example.com\n",
			"alice@\uff45xample.com", "alice@example\u3002com", "alice@exa\u00admple.com", "alice@example\uff0ecom",
			"alice@EXAMPLE.com\u2028", "\u00a0alice@example.com",
		},
		"kevin@example.com":      {"kevin@example.com", "Kevin@example.com", "\u212aevin@example.com"},
		"\u00e9lise@example.com": {"\u00e9lise@example.com", "e\u0301lise@example.com", "\u00c9LISE@example.com"},
		"a@xn--mnchen-3ya.de":    {"a@m\u00fcnchen.de", "A@M\u00dcNCHEN.DE", "a@mu\u0308nchen.de", "a@xn--mnchen-3ya.de", "a@XN--MNCHEN-3YA.DE"},
	}
	for want, spellings := range groups {
		for _, s := range spellings {
			got, err := m.ValidateAndNormalize(s)
			if err != nil || got != want {
				t.Errorf("%q -> %q, %v; want %q", s, got, err, want)
			}
		}
	}
}

// Distinct mailboxes stay distinct. The module folds spellings, not people:
// plus-tags, other domains, and characters that merely look alike do not merge.
func TestHostile_Email_distinctAddressesDoNotMerge(t *testing.T) {
	m := hostiletest.NewEmail(t)
	base, _ := m.ValidateAndNormalize("alice@example.com")
	for name, other := range map[string]string{
		"plus tag":        "alice+tag@example.com",
		"other domain":    "alice@example.org",
		"subdomain":       "alice@mail.example.com",
		"other local":     "alice2@example.com",
		"dotted local":    "a.lice@example.com",
		"cyrillic domain": "alice@\u0435xample.com",
		"greek domain":    "alice@ex\u03b1mple.com",
	} {
		got, err := m.ValidateAndNormalize(other)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got == base {
			t.Errorf("%s: %q merged into %q", name, other, base)
		}
	}
}

// A lookalike domain is delivered as its ASCII punycode, so a UI that shows
// the stored form shows the difference, and the stored form is plain ASCII.
func TestHostile_Email_homographDomainsBecomePunycode(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for name, domain := range map[string]string{
		"cyrillic a":      "\u0430pple.com",
		"cyrillic o":      "g\u043e\u043egle.com",
		"greek omicron":   "g\u03bf\u03bfgle.com",
		"latin dotless i": "\u0131cloud.com",
		"fullwidth mix":   "pay\uff50al.com",
	} {
		got, err := m.ValidateAndNormalize("a@" + domain)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		dom := got[strings.LastIndexByte(got, '@')+1:]
		for _, r := range dom {
			if r > unicode.MaxASCII {
				t.Errorf("%s: stored domain %q is not ASCII", name, dom)
			}
		}
		if name != "fullwidth mix" && !strings.Contains(dom, "xn--") {
			t.Errorf("%s: %q was not converted to punycode", name, dom)
		}
		for _, ascii := range []string{"apple.com", "google.com", "icloud.com", "paypal.com"} {
			if dom == ascii && name != "fullwidth mix" {
				t.Errorf("%s: %q folded onto the ASCII domain %q", name, domain, ascii)
			}
		}
	}
}

// Anything accepted is already in canonical form and stays accepted and
// unchanged: no accepted output carries whitespace, controls, format
// characters, upper case in the ASCII range, a non-ASCII domain, or an
// over-long part.
func TestHostile_Email_acceptedOutputIsCanonicalAndStable(t *testing.T) {
	m := hostiletest.NewEmail(t)
	corpus := []string{
		"a@b.c", "A@B.C", "x@xn--bcher-kva.de", "user.name+tag@example.co.uk", "u_s-e%r@sub.example.com",
		"\u00e9@\u00fcber.example", "a@\u65e5\u672c.jp", "a@b.c1", "!#$%&'*+-/=?^_`{|}~@example.com",
		"a@" + strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + "@example.com",
	}
	for _, in := range corpus {
		got, err := m.ValidateAndNormalize(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		again, err := m.ValidateAndNormalize(got)
		if err != nil || again != got {
			t.Errorf("%q -> %q is not stable: %q, %v", in, got, again, err)
		}
		if len(got) > 254 || strings.Count(got, "@") != 1 {
			t.Errorf("%q -> %q breaks the length or at-sign rule", in, got)
		}
		at := strings.LastIndexByte(got, '@')
		for _, r := range got[at+1:] {
			if r > unicode.MaxASCII || unicode.IsUpper(r) {
				t.Errorf("%q -> %q: the domain is not lower case ASCII", in, got)
			}
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
				t.Errorf("%q -> %q holds U+%04X", in, got, r)
			}
		}
	}
}

// The plus-addressing policy is applied to the canonical form, so no spelling
// of the tag gets past it.
func TestHostile_Email_plusAddressingPolicyCannotBeSpelledAround(t *testing.T) {
	strict := hostiletest.NewEmail(t, email.Config{RejectPlusAddressing: true})
	open := hostiletest.NewEmail(t)
	for _, s := range []string{"a+b@example.com", "A+B@EXAMPLE.COM", " a+b@example.com ", "a+@example.com", "+a@example.com", "a++b@example.com", "a+b+c@example.com"} {
		if _, err := strict.ValidateAndNormalize(s); !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("strict %q: %v, want ErrInvalidEmail", s, err)
		}
		if _, err := open.ValidateAndNormalize(s); err != nil {
			t.Errorf("open %q: %v", s, err)
		}
	}
	if got, err := strict.ValidateAndNormalize("a.b@example.com"); err != nil || got != "a.b@example.com" {
		t.Errorf("control: %q, %v", got, err)
	}
}

// Nothing in validation does I/O. A hostile address never makes it wait on the
// network, and VerifyDomain with an address that has no domain is answered
// locally.
func TestHostile_Email_verifyDomainRefusesWithoutNetwork(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for addr, want := range map[string]error{
		"nodomain": email.ErrDomainNoMX,
		"":         email.ErrDomainNoMX,
		"user@":    email.ErrDomainNoMX,
		"user@" + strings.Repeat("a", 64) + ".com": email.ErrInvalidEmail,
		"user@a..com": email.ErrInvalidEmail,
	} {
		start := time.Now()
		if err := m.VerifyDomain(t.Context(), addr); !errors.Is(err, want) {
			t.Errorf("VerifyDomain(%.30q) = %v, want %v", addr, err, want)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("VerifyDomain(%.30q) took %v: it went to the network", addr, d)
		}
	}
}

// Construction.
func TestHostile_Email_constructionRefusesAnUnusableProvider(t *testing.T) {
	if _, err := email.New(nil); !errors.Is(err, email.ErrInvalidConfig) {
		t.Errorf("nil provider: %v", err)
	}
}
