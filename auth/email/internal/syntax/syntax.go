// Package syntax checks the structure of a normalized email address against
// RFC 5321 / RFC 5322.
package syntax

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

// Validate checks address against RFC 5321 / RFC 5322 rules.
// It uses net/mail for syntax and then applies stricter structural checks.
func Validate(address string) error {
	if len(address) == 0 {
		return errs.Invalid(fmt.Errorf("must not be empty"))
	}
	if len(address) > 254 {
		return errs.Invalid(fmt.Errorf("must be at most 254 characters"))
	}

	// net/mail.ParseAddress handles RFC 5322 syntax (quoted strings, comments, etc.).
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return errs.Invalid(fmt.Errorf("invalid format"))
	}

	// Reject display names like "Ana García <ana@example.com>".
	// EqualFold is intentional: net/mail may normalize domain case, so a
	// direct == would reject valid addresses when Validate is called without
	// prior normalization (e.g. "User@EXAMPLE.COM" vs "User@example.com").
	if !strings.EqualFold(address, parsed.Address) {
		return errs.Invalid(fmt.Errorf("invalid format"))
	}

	atIdx := strings.LastIndexByte(parsed.Address, '@')
	local := parsed.Address[:atIdx]
	domain := parsed.Address[atIdx+1:]

	if len(local) > 64 {
		return errs.Invalid(fmt.Errorf("local part must be at most 64 characters"))
	}

	// Reject address literals like "user@[192.168.1.1]" or "user@[IPv6:...]".
	// net/mail accepts them, but they are almost never wanted in an account
	// system, cannot be MX-verified, and would otherwise slip through the
	// dot/label checks below (the bracketed octets look like labels).
	if strings.HasPrefix(domain, "[") {
		return errs.Invalid(fmt.Errorf("domain must not be an address literal"))
	}

	return validateDomain(domain)
}

// validateDomain applies the domain rules: at least one dot, no
// leading/trailing/consecutive dots, each label 1–63 characters, and a
// top-level label that is not all digits.
func validateDomain(domain string) error {
	hasDot := false
	labelLen := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if labelLen == 0 {
				return errs.Invalid(fmt.Errorf("domain must not start with or contain consecutive dots"))
			}
			hasDot = true
			labelLen = 0
		} else {
			labelLen++
			if labelLen > 63 {
				return errs.Invalid(fmt.Errorf("each domain label must be at most 63 characters"))
			}
		}
	}
	if !hasDot {
		return errs.Invalid(fmt.Errorf("domain must contain at least one dot"))
	}
	if labelLen == 0 {
		return errs.Invalid(fmt.Errorf("domain must not end with a dot"))
	}
	// An all-digit top-level label is a bare IPv4 address ("user@127.0.0.1")
	// or no domain at all (RFC 3696 section 2). It is the address literal
	// refused above in another spelling, and it was accepted until 2026-09-25.
	if allDigits(domain[strings.LastIndexByte(domain, '.')+1:]) {
		return errs.Invalid(fmt.Errorf("top-level domain must not be all digits"))
	}

	return nil
}

// allDigits reports whether s is non-empty and made of ASCII digits only.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
