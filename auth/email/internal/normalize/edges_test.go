package normalize_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/normalize"
)

// The domain is converted wherever the at sign sits, including at position 0.
func TestAddressConvertsTheDomainOfAnAddressWithoutALocalPart(t *testing.T) {
	t.Parallel()
	got, err := normalize.Address("@BÜCHER.de")
	if err != nil || got != "@xn--bcher-kva.de" {
		t.Fatalf("Address = %q, %v; want the domain in ASCII form", got, err)
	}
}

// A domain that is not UTF-8 has no canonical form: it is refused here rather
// than handed to IDNA, which would read each bad byte as U+FFFD.
func TestAddressRefusesADomainThatIsNotUTF8(t *testing.T) {
	t.Parallel()
	got, err := normalize.Address("a@\xff.com")
	if !errors.Is(err, email.ErrInvalidEmail) || got != "" {
		t.Fatalf("Address = %q, %v; want ErrInvalidEmail", got, err)
	}
}
