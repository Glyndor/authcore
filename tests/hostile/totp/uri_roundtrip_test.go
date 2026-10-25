package totp_test

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/totp"
)

// splitLabel reads the label the way an authenticator app does: on the encoded
// path, at the first literal colon, then percent-decoding each side. The
// module writes every colon inside a name as %3A, so the first literal colon
// can only be the separator.
func splitLabel(t testing.TB, rawPath string) (issuer, account string) {
	t.Helper()
	label := strings.TrimPrefix(rawPath, "/")
	head, tail, found := strings.Cut(label, ":")
	if !found {
		head, tail = "", label
	}
	var err error
	if issuer, err = url.PathUnescape(head); err != nil {
		t.Fatalf("issuer part %q: %v", head, err)
	}
	if account, err = url.PathUnescape(tail); err != nil {
		t.Fatalf("account part %q: %v", tail, err)
	}
	return issuer, account
}

// For any issuer and account name, including spaces, reserved characters,
// colons, percent signs, non-ASCII text, and bidirectional controls, the URI an
// app reads gives back exactly the issuer and the account that went in, the
// enrolled secret, and the fixed algorithm, digits and period, each once. A
// name an app would read differently from the way it was given is a way to
// show the user one account and enrol another.
func TestHostile_URI_issuerAndAccountSurviveTheRoundTrip(t *testing.T) {
	names := []string{
		"alice", "alice@example.com", "alice smith", "alice+tag@example.com", "a:b", "a:b:c", ":", "::a", "a::",
		"100%", "%3A", "%253A", "a%20b", "a b+c d", "a&b=c", "a?b#c", "a/b\\c", "a;b,c", "\"q\" 'q' <t>",
		"Señor López", "日本語", "\U0001f600", "é", "العربية",
		"left‮right", "zero​width", "tab\there", "line\nbreak", "nul\x00byte", strings.Repeat("x", 1000),
	}
	for _, issuer := range append([]string{"Acme", "Acme Co", "Acme:Co"}, names...) {
		if !utf8.ValidString(issuer) {
			continue
		}
		m := newModule(t, totp.Config{Issuer: issuer})
		for _, account := range names {
			enr, err := m.Enroll(account)
			if err != nil {
				t.Fatalf("Enroll(%q) with issuer %q: %v", account, issuer, err)
			}
			u, err := url.Parse(enr.URI)
			if err != nil {
				t.Errorf("issuer %q account %q: URI does not parse: %v", issuer, account, err)
				continue
			}
			gotIssuer, gotAccount := splitLabel(t, u.EscapedPath())
			if gotAccount != account {
				t.Errorf("issuer %q account %q: the app reads the account as %q", issuer, account, gotAccount)
			}
			if issuer != "" && gotIssuer != issuer {
				t.Errorf("issuer %q account %q: the app reads the label issuer as %q", issuer, account, gotIssuer)
			}
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				t.Errorf("issuer %q account %q: query: %v", issuer, account, err)
				continue
			}
			for key, want := range map[string]string{"secret": enr.Secret, "algorithm": "SHA1", "digits": "6", "period": "30", "issuer": issuer} {
				if vals := q[key]; len(vals) != 1 || vals[0] != want {
					t.Errorf("issuer %q account %q: %s = %q, want exactly [%q]", issuer, account, key, vals, want)
				}
			}
			if len(q) != 5 {
				t.Errorf("issuer %q account %q: %d query keys %v, want 5", issuer, account, len(q), q)
			}
		}
	}
}
