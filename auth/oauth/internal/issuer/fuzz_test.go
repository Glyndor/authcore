package issuer_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/issuer"
)

// isHexGUID is an independent reading of the tenant id shape: 8-4-4-4-12 ASCII
// hex digits, nothing else. It is written as a loop on purpose, so the fuzz
// compares the package's pattern with something that shares no code with it.
func isHexGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// FuzzIssuerPredicates compares the three issuer predicates with independent
// definitions. These are the only places the library approves a family of
// issuers, so a pattern that is one character too generous would accept
// tokens from an issuer nobody meant to trust.
func FuzzIssuerPredicates(f *testing.F) {
	f.Add("https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0")
	f.Add("https://login.microsoftonline.com/common/v2.0")
	f.Add("https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0\n")
	f.Add("x https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0")
	f.Add("9188040d-6c67-4c5b-b112-36a304b66dad")
	f.Add("9188040d-6c67-4c5b-b112-36a304b66dad\n")
	f.Add("accounts.google.com")
	f.Add("https://accounts.google.com")
	f.Add("")

	const prefix, suffix = "https://login.microsoftonline.com/", "/v2.0"
	f.Fuzz(func(t *testing.T, s string) {
		wantAzure := len(s) == len(prefix)+36+len(suffix) && s[:len(prefix)] == prefix && s[len(prefix)+36:] == suffix && isHexGUID(s[len(prefix):len(prefix)+36])
		if got := issuer.AzureV2(s); got != wantAzure {
			t.Fatalf("AzureV2(%q) = %v, independent reading says %v", s, got, wantAzure)
		}
		if got := issuer.IsTenantGUID(s); got != isHexGUID(s) {
			t.Fatalf("IsTenantGUID(%q) = %v, independent reading says %v", s, got, isHexGUID(s))
		}
		wantGoogle := s == "https://accounts.google.com" || s == "accounts.google.com"
		if got := issuer.Google(s); got != wantGoogle {
			t.Fatalf("Google(%q) = %v, want %v", s, got, wantGoogle)
		}
	})
}
