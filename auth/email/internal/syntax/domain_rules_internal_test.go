package syntax

import "testing"

// Validate rejects a domain with an empty label before it reaches
// validateDomain, so the rules inside it are only reachable by calling it
// directly. They are the second line of defence, and this pins them so that
// relaxing the check in front of them cannot let a malformed domain through
// without a test going red.
func TestValidateDomainRefusesEmptyLabelsOnItsOwn(t *testing.T) {
	for _, domain := range []string{".example.com", "example..com", "example.com.", "a.b.1", "nodot", ""} {
		if err := validateDomain(domain); err == nil {
			t.Errorf("validateDomain(%q) accepted a malformed domain", domain)
		}
	}
	if err := validateDomain("example.com"); err != nil {
		t.Errorf("validateDomain(example.com) = %v, want nil", err)
	}
}

func TestAllDigitsIsFalseForTheEmptyString(t *testing.T) {
	if allDigits("") {
		t.Error("an empty string is not all digits")
	}
	if !allDigits("123") || allDigits("12a") {
		t.Error("allDigits does not tell digits from letters")
	}
}
