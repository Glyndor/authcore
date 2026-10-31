package otpauth

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzURI builds a provisioning URI from arbitrary issuer and account text. The
// URI must always parse, hold exactly one secret and the fixed algorithm,
// digits and period, carry the issuer it was given, contain no raw control or
// non-ASCII byte, and keep at most one raw colon in its label.
func FuzzURI(f *testing.F) {
	for _, s := range [][2]string{
		{"", ""}, {"Acme", "alice@example.com"}, {"Acme:Co", "alice/a:b%é"}, {"Acme:Co", "a:b"}, {"A&secret=X", "b&secret=Y"},
		{"x", "y#z?w"}, {"\x00", "\n"}, {"\u00dc", "\u65e5\u672c"}, {"%", "%00"}, {"a/b", "../c"},
		{"\xff", "\xfe"}, {strings.Repeat("a", 5000), "z"},
	} {
		f.Add(s[0], s[1])
	}
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	f.Fuzz(func(t *testing.T, issuer, account string) {
		uri := URI(issuer, account, secret)
		for i := 0; i < len(uri); i++ {
			if c := uri[i]; c < 0x21 || c > 0x7e || c == '"' || c == '<' || c == '>' {
				t.Fatalf("raw byte %#x at %d in %.60q", c, i, uri)
			}
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("does not parse: %v: %.60q", err, uri)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" {
			t.Fatalf("scheme=%q host=%q fragment=%q", u.Scheme, u.Host, u.Fragment)
		}
		assertLabel(t, u, issuer, account)
		q := u.Query()
		for k, want := range map[string]string{"secret": secret, "algorithm": "SHA1", "digits": "6", "period": "30"} {
			if v := q[k]; len(v) != 1 || v[0] != want {
				t.Fatalf("%s = %q, want [%q]", k, v, want)
			}
		}
		wantKeys, wantColons := 4, 0
		if issuer != "" {
			wantKeys, wantColons = 5, 1
			if v := q["issuer"]; len(v) != 1 || v[0] != issuer {
				t.Fatalf("issuer = %q, want [%q]", v, issuer)
			}
		}
		if len(q) != wantKeys {
			t.Fatalf("%d query keys, want %d: %v", len(q), wantKeys, q)
		}
		if n := strings.Count(u.EscapedPath(), ":"); n != wantColons {
			t.Fatalf("%d raw colons in the label %q, want %d", n, u.EscapedPath(), wantColons)
		}
	})
}

func assertLabel(t *testing.T, u *url.URL, issuer, account string) {
	t.Helper()
	want := account
	if issuer != "" {
		want = issuer + ":" + account
	}
	label, err := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/"))
	if err != nil || label != want {
		t.Fatalf("label=%q, %v; want %q", label, err, want)
	}
}
