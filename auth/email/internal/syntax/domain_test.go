package syntax_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/syntax"
)

// Each refusal is paired with an address of the same shape that is accepted.
func TestValidate_domainRules(t *testing.T) {
	cases := []struct {
		name, addr, reason string
	}{
		{"label over 63 bytes", "user@" + strings.Repeat("a", 64) + ".com", "each domain label must be at most 63 characters"},
		{"address literal", "user@[192.168.1.1]", "domain must not be an address literal"},
		{"no dot", "user@localhost", "domain must contain at least one dot"},
		{"all-digit top-level label", "user@127.0.0.1", "top-level domain must not be all digits"},
		{"all-digit short domain", "user@1.2", "top-level domain must not be all digits"},
	}
	for _, c := range cases {
		err := syntax.Validate(c.addr)
		if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v, want ErrInvalidEmail with %q", c.name, err, c.reason)
		}
	}
	for _, addr := range []string{
		"user@" + strings.Repeat("a", 63) + ".com",
		"user@123.example.com",
		"user@example.co1",
	} {
		if err := syntax.Validate(addr); err != nil {
			t.Errorf("%s: %v, want accepted", addr, err)
		}
	}
}

func TestValidate_refusesWhatNetMailRejects(t *testing.T) {
	for _, addr := range []string{"not an address", "@example.com", "user@"} {
		err := syntax.Validate(addr)
		if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "invalid format") {
			t.Errorf("%q: %v, want the invalid-format refusal", addr, err)
		}
	}
}
