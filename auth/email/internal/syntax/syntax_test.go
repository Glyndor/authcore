package syntax_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/syntax"
)

// ---- validate() — valid addresses (internal) --------------------------------

func TestValidate_simpleValid(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"a@b.io",
		"user@sub.domain.example.com",
	}
	for _, addr := range valid {
		if err := syntax.Validate(addr); err != nil {
			t.Errorf("syntax.Validate(%q) = %v, want nil", addr, err)
		}
	}
}

// ---- validate() — invalid addresses (internal) ------------------------------

func TestValidate_empty(t *testing.T) {
	if err := syntax.Validate(""); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_tooLong(t *testing.T) {
	local := "a"
	for len(local+"@b.com") <= 254 {
		local += "a"
	}
	if err := syntax.Validate(local + "@b.com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail for too-long address")
	}
}

func TestValidate_noAt(t *testing.T) {
	if err := syntax.Validate("userexample.com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_localPartTooLong(t *testing.T) {
	local := ""
	for i := 0; i < 65; i++ {
		local += "a"
	}
	if err := syntax.Validate(local + "@example.com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail for local part > 64 chars")
	}
}

func TestValidate_domainNoDot(t *testing.T) {
	if err := syntax.Validate("user@localhost"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainLeadingDot(t *testing.T) {
	if err := syntax.Validate("user@.example.com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainTrailingDot(t *testing.T) {
	if err := syntax.Validate("user@example.com."); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainConsecutiveDots(t *testing.T) {
	if err := syntax.Validate("user@example..com"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_withDisplayName(t *testing.T) {
	if err := syntax.Validate("Ana <ana@example.com>"); !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("expected email.ErrInvalidEmail for display name format")
	}
}

func TestValidate_addressLiteralRejected(t *testing.T) {
	for _, addr := range []string{
		"user@[192.168.1.1]",
		"user@[IPv6:2001:db8::1]",
	} {
		if err := syntax.Validate(addr); !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("expected email.ErrInvalidEmail for address literal %q, got %v", addr, err)
		}
	}
}

// ---- email.ErrInvalidEmail wraps a reason -----------------------------------------

func TestValidate_wrapsReason(t *testing.T) {
	err := syntax.Validate("")
	if !errors.Is(err, email.ErrInvalidEmail) {
		t.Fatalf("expected email.ErrInvalidEmail, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil {
		t.Fatal("expected wrapped reason, got nil")
	}
	if reason.Error() == "" {
		t.Error("wrapped reason must not be empty")
	}
}

func TestValidate_tooLongWithEveryPartIndividuallyLegal(t *testing.T) {
	local := strings.Repeat("a", 60) // under the 64 limit
	label := strings.Repeat("b", 60) // under the 63-byte DNS label limit
	domain := label + "." + label + "." + label + "." + label + ".com"
	address := local + "@" + domain

	if len(address) <= 254 {
		t.Fatalf("fixture is only %d characters, it has to exceed 254 to test anything", len(address))
	}
	if len(local) > 64 {
		t.Fatal("fixture's local part breaks its own premise")
	}

	err := syntax.Validate(address)
	if !errors.Is(err, email.ErrInvalidEmail) {
		t.Fatalf("an address over 254 characters must be refused, got: %v", err)
	}
	if !strings.Contains(err.Error(), "254") {
		t.Fatalf("refused for the wrong reason — the length guard is not what caught it: %v", err)
	}
}

// The companion: the same shape just under the limit has to be accepted, or
// the test above would pass for any address at all.
func TestValidate_acceptsALongButLegalAddress(t *testing.T) {
	local := strings.Repeat("a", 60)
	label := strings.Repeat("b", 60)
	address := local + "@" + label + "." + label + ".com"

	if len(address) > 254 {
		t.Fatalf("fixture is %d characters, it has to stay under 254", len(address))
	}
	if err := syntax.Validate(address); err != nil {
		t.Fatalf("a long but legal address must be accepted: %v", err)
	}
}
