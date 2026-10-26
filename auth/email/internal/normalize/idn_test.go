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

// A domain whose ASCII form is not itself a valid name has no canonical form:
// storing it would make the second pass over the stored value refuse what the
// first one accepted.
func TestAddress_refusesADomainThatDoesNotSurviveASecondPass(t *testing.T) {
	_, err := normalize.Address("a@\u2137a.example")
	if !errors.Is(err, email.ErrInvalidEmail) {
		t.Fatalf("got %v, want ErrInvalidEmail", err)
	}
}

func TestAddress_isAFixedPointForAcceptedDomains(t *testing.T) {
	for _, in := range []string{"User@München.DE", "a@example.com", "a@EXAMPLE.com", "a@bücher.example"} {
		first, err := normalize.Address(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		second, err := normalize.Address(first)
		if err != nil || second != first {
			t.Errorf("%q: %q then %q (%v), want the same form", in, first, second, err)
		}
	}
}
