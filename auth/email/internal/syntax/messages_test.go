package syntax_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/syntax"
)

func TestValidateNamesTheFirstRuleThatFails(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]string{
		"":                 "must not be empty",
		"a":                "invalid format",
		"user@example.123": "top-level domain must not be all digits",
		"user@[1.2.3.4]":   "address literal",
		"user@nodot":       "at least one dot",
	} {
		err := syntax.Validate(addr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Validate(%q) = %v, want a refusal that says %q", addr, err, want)
		}
	}
}
