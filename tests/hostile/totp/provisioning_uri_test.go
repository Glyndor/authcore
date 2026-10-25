package totp_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// The provisioning URI is built from the account name and the issuer, both of
// which an attacker may choose (a display name, an email local part). Whatever
// they contain, the URI that comes out has one secret, the fixed algorithm,
// digits and period, and the label and issuer it was given.
func TestHostile_Enroll_provisioningURIResistsInjection(t *testing.T) {
	hostile := map[string]string{
		"extra secret param":  "alice&secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"question mark":       "alice?secret=AAAA",
		"fragment":            "alice#secret=AAAA",
		"override algorithm":  "alice@example.com&algorithm=SHA512&digits=8&period=60",
		"semicolon":           "alice;secret=AAAA",
		"path traversal":      "../../evil",
		"colon":               "evil:alice",
		"double colon":        "a:b:c",
		"percent sequences":   "%00%0d%0a%26secret%3dAAAA",
		"literal percent":     "100%",
		"newline":             "alice\nsecret=AAAA",
		"carriage return":     "alice\r\nHost: evil",
		"NUL":                 "alice\x00",
		"space":               "alice smith",
		"plus":                "alice+tag@example.com",
		"slash":               "a/b",
		"backslash":           `a\b`,
		"quotes":              `"alice"'`,
		"angle brackets":      "<script>alert(1)</script>",
		"unicode":             "Se\u00f1or L\u00f3pez \u65e5\u672c",
		"bidi override":       "alice\u202egnp.exe",
		"empty":               "",
		"very long":           strings.Repeat("a", 4096),
		"invalid UTF-8":       "alice\xff\xfe",
		"scheme confusion":    "javascript:alert(1)",
		"authority confusion": "//evil.example/x",
	}
	for name, account := range hostile {
		for _, issuer := range []string{"", "Acme", "Evil&secret=AAAA", "Acme:Co", "A/B?c#d", "\u00dcber Corp"} {
			m := newModule(t, totp.Config{Issuer: issuer})
			enr, err := m.Enroll(account)
			if err != nil {
				t.Fatalf("%s/%q: Enroll: %v", name, issuer, err)
			}
			checkURI(t, fmt.Sprintf("%s/%q", name, issuer), enr, issuer)
		}
	}
}

// hasRawUnsafeByte reports the first byte of uri that must have been escaped.
func hasRawUnsafeByte(uri string) (int, bool) {
	for i := 0; i < len(uri); i++ {
		if c := uri[i]; c < 0x20 || c == 0x7f || c == ' ' || c == '"' || c == '<' || c == '>' || c >= 0x80 {
			return i, true
		}
	}
	return 0, false
}

func checkURI(t *testing.T, label string, enr *totp.Enrollment, issuer string) {
	t.Helper()
	if i, bad := hasRawUnsafeByte(enr.URI); bad {
		t.Errorf("%s: the URI holds the raw byte %#x at %d: %.80q", label, enr.URI[i], i, enr.URI)
		return
	}
	u, err := url.Parse(enr.URI)
	if err != nil {
		t.Errorf("%s: the URI does not parse: %v", label, err)
		return
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" || u.User != nil {
		t.Errorf("%s: scheme=%q host=%q fragment=%q user=%v", label, u.Scheme, u.Host, u.Fragment, u.User)
	}
	q := u.Query()
	for key, want := range map[string]string{"secret": enr.Secret, "algorithm": "SHA1", "digits": "6", "period": "30"} {
		if vals := q[key]; len(vals) != 1 || vals[0] != want {
			t.Errorf("%s: %s = %q, want exactly [%q]", label, key, vals, want)
		}
	}
	// The first colon of the label separates issuer from account, so a colon
	// inside either must have been escaped: one raw colon with an issuer, none
	// without.
	wantColons := 0
	if issuer != "" {
		wantColons = 1
	}
	if got := strings.Count(u.EscapedPath(), ":"); got != wantColons {
		t.Errorf("%s: the label holds %d raw colons, want %d: %s", label, got, wantColons, u.EscapedPath())
	}
	wantKeys := 4
	if issuer != "" {
		wantKeys = 5
		if vals := q["issuer"]; len(vals) != 1 || vals[0] != issuer {
			t.Errorf("%s: issuer = %q, want [%q]", label, vals, issuer)
		}
	}
	if len(q) != wantKeys {
		t.Errorf("%s: the URI carries %d query keys, want %d: %v", label, len(q), wantKeys, q)
	}
}
