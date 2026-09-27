package totp

// Second half of the totp test suite, split from totp_test.go to stay under
// the repository's per-file line limit. Shares that file's fixtures
// (newTOTP, fakeProvider, fixed clocks) because both live in package totp.

import (
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// ---- Enroll -----------------------------------------------------------------

func TestEnroll_UniqueSecretsAndCodes(t *testing.T) {
	mod := newTOTP(t, Config{Issuer: "Acme", RecoveryCodeCount: 5})
	a, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	b, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if a.Secret == b.Secret {
		t.Error("two Enroll calls produced the same secret")
	}
	if len(a.RecoveryCodes) != 5 || len(b.RecoveryCodes) != 5 {
		t.Fatalf("RecoveryCodes length = %d and %d, want 5", len(a.RecoveryCodes), len(b.RecoveryCodes))
	}
	for i := range a.RecoveryCodes {
		if a.RecoveryCodes[i] == b.RecoveryCodes[i] {
			t.Errorf("recovery code %d matched between enrollments", i)
		}
	}
}

func TestEnroll_SecretShape(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(enr.Secret) != 32 {
		t.Errorf("secret length = %d, want 32 (20 bytes base32 no padding)", len(enr.Secret))
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret); err != nil {
		t.Errorf("secret is not valid base32: %v", err)
	}
}

func TestEnroll_RecoveryCodesShape(t *testing.T) {
	mod := newTOTP(t, Config{RecoveryCodeCount: 8})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(enr.RecoveryCodes) != 8 || len(enr.RecoveryHashes) != 8 {
		t.Fatalf("recovery slice length = %d/%d, want 8", len(enr.RecoveryCodes), len(enr.RecoveryHashes))
	}
	for i, c := range enr.RecoveryCodes {
		// "XXXXXXXX-XXXXXXXX" -> 8 + 1 + 8 = 17 chars, base32 only.
		if len(c) != 17 {
			t.Errorf("recovery code %d has length %d, want 17", i, len(c))
		}
		if c[8] != '-' {
			t.Errorf("recovery code %d missing hyphen at position 8: %q", i, c)
		}
		plain := strings.ReplaceAll(c, "-", "")
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(plain); err != nil {
			t.Errorf("recovery code %d not valid base32: %v", i, err)
		}
		// Hash must be a hex-encoded HMAC-SHA256: 64 lowercase hex chars.
		if len(enr.RecoveryHashes[i]) != 64 {
			t.Errorf("recovery hash %d has length %d, want 64", i, len(enr.RecoveryHashes[i]))
		}
	}
}

// ---- URI --------------------------------------------------------------------

func TestEnroll_URI_RoundTrips(t *testing.T) {
	mod := newTOTP(t, Config{Issuer: "Acme Corp"})
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
	mod := newTOTP(t, Config{Issuer: "Acme"})
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

// ---- Recovery codes ---------------------------------------------------------

func TestVerifyRecoveryCode_AllMatch(t *testing.T) {
	mod := newTOTP(t, Config{RecoveryCodeCount: 8})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for i, c := range enr.RecoveryCodes {
		gotIdx, ok := mod.VerifyRecoveryCode(c, enr.RecoveryHashes)
		if !ok {
			t.Errorf("recovery code %d (%q) did not verify", i, c)
			continue
		}
		if gotIdx != i {
			t.Errorf("recovery code %d returned index %d", i, gotIdx)
		}
	}
}

func TestVerifyRecoveryCode_WrongCode(t *testing.T) {
	mod := newTOTP(t, Config{RecoveryCodeCount: 4})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, ok := mod.VerifyRecoveryCode("AAAA1111-BBBB2222", enr.RecoveryHashes); ok {
		t.Error("a non-mint code verified as if it were in the list")
	}
	if _, ok := mod.VerifyRecoveryCode("", enr.RecoveryHashes); ok {
		t.Error("empty code verified")
	}
}

func TestVerifyRecoveryCode_Normalisation(t *testing.T) {
	mod := newTOTP(t, Config{RecoveryCodeCount: 4})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	c := enr.RecoveryCodes[2]

	variants := []string{
		c,                               // as-is
		strings.ReplaceAll(c, "-", ""),  // no hyphen
		strings.ToUpper(c),              // uppercase (base32 letters)
		strings.ReplaceAll(c, "-", " "), // space instead of hyphen
		strings.ReplaceAll(strings.ToUpper(c), "-", " "),
	}
	for _, v := range variants {
		idx, ok := mod.VerifyRecoveryCode(v, enr.RecoveryHashes)
		if !ok || idx != 2 {
			t.Errorf("variant %q failed to verify (idx=%d ok=%v)", v, idx, ok)
		}
	}
}

func TestVerifyRecoveryCode_EmptyList(t *testing.T) {
	mod := newTOTP(t)
	if idx, ok := mod.VerifyRecoveryCode("ABCD1234-EFGH5678", nil); ok {
		t.Errorf("non-empty code matched an empty hash list (idx=%d)", idx)
	}
}

func TestHashRecoveryCode_MatchesEnrollmentHashes(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for i, c := range enr.RecoveryCodes {
		got, err := mod.HashRecoveryCode(c)
		if err != nil || got != enr.RecoveryHashes[i] {
			t.Errorf("HashRecoveryCode(%q) = %q, %v; want %q", c, got, err, enr.RecoveryHashes[i])
		}
	}
}

func TestHashRecoveryCode_Peppered(t *testing.T) {
	// Hashing the same code under two different refresh secrets must
	// produce different digests; otherwise the pepper is not applied.
	p1 := newFakeProvider(t)
	p2 := fakeProvider{keys: fakeKeys{secret: []byte(strings.Repeat("z", 32))}}
	m1, _ := New(p1)
	m2, _ := New(p2)
	h1, err1 := m1.HashRecoveryCode("ABCD1234-EFGH5678")
	h2, err2 := m2.HashRecoveryCode("ABCD1234-EFGH5678")
	if err1 != nil || err2 != nil {
		t.Fatalf("HashRecoveryCode: %v, %v", err1, err2)
	}
	if h1 == h2 {
		t.Error("hash is identical under different server secrets; HMAC pepper is not applied")
	}
}

// ---- validateConfig --------------------------------------------------------

func TestValidateConfig_Rejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"SkewSteps above cap", Config{SkewSteps: Int(11)}},
		{"negative SkewSteps", Config{SkewSteps: Int(-1)}},
		{"RecoveryCodeCount below floor", Config{RecoveryCodeCount: -1}},
		{"RecoveryCodeCount 51", Config{RecoveryCodeCount: 51}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(newFakeProvider(t), c.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("New(%+v) = %v, want ErrInvalidConfig", c.cfg, err)
			}
		})
	}
}

func TestValidateConfig_RecoveryCodeCountZeroFallsBackToDefault(t *testing.T) {
	// RecoveryCodeCount 0 falls back to the default (10) via applyDefaults,
	// so it must NOT be rejected by validateConfig.
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 0}); err != nil {
		t.Errorf("RecoveryCodeCount 0 should default, got %v", err)
	}
}

func TestValidateConfig_Boundaries(t *testing.T) {
	// SkewSteps exactly at the cap (10) must be accepted.
	if _, err := New(newFakeProvider(t), Config{SkewSteps: Int(10)}); err != nil {
		t.Errorf("SkewSteps=10 should be accepted: %v", err)
	}
	// RecoveryCodeCount at the boundaries (1, 50) must be accepted.
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 1}); err != nil {
		t.Errorf("RecoveryCodeCount=1 should be accepted: %v", err)
	}
	if _, err := New(newFakeProvider(t), Config{RecoveryCodeCount: 50}); err != nil {
		t.Errorf("RecoveryCodeCount=50 should be accepted: %v", err)
	}
}
