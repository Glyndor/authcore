package normalize_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/normalize"
)

func TestAddress_convertsIDNDomainToPunycode(t *testing.T) {
	got, err := normalize.Address("User@München.DE")
	if err != nil || got != "user@xn--mnchen-3ya.de" {
		t.Errorf("got %q, %v; want user@xn--mnchen-3ya.de", got, err)
	}
}

func TestAddress_addressWithoutAtIsOnlyTrimmedAndLowercased(t *testing.T) {
	got, err := normalize.Address("  NotAnEmail ")
	if err != nil || got != "notanemail" {
		t.Errorf("got %q, %v; want notanemail", got, err)
	}
}

func TestAddress_refusesADomainIDNAForbids(t *testing.T) {
	_, err := normalize.Address("user@-bad.example")
	if !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "not a valid internationalised name") {
		t.Errorf("leading hyphen label: %v, want the IDNA refusal", err)
	}
}

func TestAddress_refusesAnInvisibleLocalPart(t *testing.T) {
	_, err := normalize.Address("admin\u200b@example.com")
	if !errors.Is(err, email.ErrInvalidEmail) {
		t.Errorf("zero width space: %v, want ErrInvalidEmail", err)
	}
}
