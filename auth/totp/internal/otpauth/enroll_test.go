package otpauth_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// ---- URI --------------------------------------------------------------------

func TestEnroll_URI_RoundTrips(t *testing.T) {
	mod := newTOTP(t, totp.Config{Issuer: "Acme Corp"})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	u, err := url.Parse(enr.URI)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", enr.URI, err)
	}
	if u.Scheme != "otpauth" {
		t.Errorf("scheme = %q, want otpauth", u.Scheme)
	}
	if u.Host != "totp" {
		t.Errorf("host = %q, want totp", u.Host)
	}
	// The label is escaped once: the raw URI carries %20, and a parser (or
	// an authenticator) decodes it back to the issuer as typed. Before
	// 2026-09-25 this test pinned the double-escaped "%2520".
	if !strings.HasPrefix(enr.URI, "otpauth://totp/Acme%20Corp:alice@example.com?") {
		t.Errorf("URI = %q, want the label escaped once", enr.URI)
	}
	if u.Path != "/Acme Corp:alice@example.com" {
		t.Errorf("path = %q, want /Acme Corp:alice@example.com", u.Path)
	}
	q := u.Query()
	if q.Get("secret") != enr.Secret {
		t.Errorf("secret query = %q, want %q", q.Get("secret"), enr.Secret)
	}
	if q.Get("issuer") != "Acme Corp" {
		t.Errorf("issuer query = %q, want %q", q.Get("issuer"), "Acme Corp")
	}
	if q.Get("algorithm") != "SHA1" {
		t.Errorf("algorithm = %q, want SHA1", q.Get("algorithm"))
	}
	if q.Get("digits") != "6" {
		t.Errorf("digits = %q, want 6", q.Get("digits"))
	}
	if q.Get("period") != "30" {
		t.Errorf("period = %q, want 30", q.Get("period"))
	}
}

// TestEnroll_URI_AwkwardAccountName verifies the URI survives account
// names containing a colon, a space and a non-ASCII character.
func TestEnroll_URI_AwkwardAccountName(t *testing.T) {
	mod := newTOTP(t, totp.Config{Issuer: "Acme"})
	enr, err := mod.Enroll("Señor López:work@acme.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	u, err := url.Parse(enr.URI)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", enr.URI, err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Errorf("unexpected host part: scheme=%q host=%q", u.Scheme, u.Host)
	}
	// The escaped path keeps exactly one literal colon, the separator, and
	// percent-encodes everything awkward inside each part once, the colon
	// in the account included. Before 2026-09-25 the test compared against
	// a double-escaped path.
	wantEscaped := "/Acme:Se%C3%B1or%20L%C3%B3pez%3Awork@acme.com"
	if u.EscapedPath() != wantEscaped {
		t.Errorf("escaped path = %q, want %q", u.EscapedPath(), wantEscaped)
	}
	parts := strings.SplitN(strings.TrimPrefix(u.EscapedPath(), "/"), ":", 2)
	issuer, errI := url.PathUnescape(parts[0])
	account, errA := url.PathUnescape(parts[1])
	if errI != nil || errA != nil || issuer != "Acme" || account != "Señor López:work@acme.com" {
		t.Errorf("label splits into %q / %q (%v, %v), want Acme / the account as typed", issuer, account, errI, errA)
	}
}

func TestEnroll_URI_NoIssuer(t *testing.T) {
	// Empty Issuer means the URI is built without the issuer parameter
	// and the label, so the path is just "/" + account.
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	u, err := url.Parse(enr.URI)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Path != "/alice@example.com" {
		t.Errorf("path = %q, want /alice@example.com", u.Path)
	}
	if u.Query().Get("issuer") != "" {
		t.Errorf("issuer query should be empty, got %q", u.Query().Get("issuer"))
	}
}
