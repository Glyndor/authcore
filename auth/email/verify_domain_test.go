package email

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestVerifyDomain_noAtSignReturnsErrDomainNoMX(t *testing.T) {
	m := newMod(t)
	err := m.VerifyDomain(context.Background(), "notanemail")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("expected ErrDomainNoMX for address with no '@', got %v", err)
	}
}

// VerifyDomain refuses a value no DNS name can have before the cache or the
// resolver sees it, so unvalidated input cannot pin memory in the cache.
func TestVerifyDomain_refusesAnImplausibleDomainWithoutLookingItUp(t *testing.T) {
	m := newMod(t)
	for _, domain := range []string{strings.Repeat("a", 250) + ".com", strings.Repeat("b", 64) + ".example"} {
		err := m.VerifyDomain(context.Background(), "user@"+domain)
		if !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%d-byte domain: %v, want ErrInvalidEmail", len(domain), err)
		}
	}
}
