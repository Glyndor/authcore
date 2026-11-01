package normalize_test

import (
	"errors"
	"strings"
	"testing"
	"time"

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

// The punycode step of IDNA is quadratic in the number of distinct code
// points, and the 254 byte limit used to be checked after it: a body of
// distinct characters cost seconds to minutes of CPU before it was refused.
// 40000 distinct ideographs took about eleven seconds without the early limit.
func TestAddress_aHugeDomainIsRefusedBeforeIDNA(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40000; i++ {
		b.WriteRune(rune(0x4E00 + i))
	}
	start := time.Now()
	_, err := normalize.Address("a@" + b.String() + ".com")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v: the input reached IDNA before being limited", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "at most 254 characters") {
		t.Errorf("err = %v, want the 254 character refusal", err)
	}
}
