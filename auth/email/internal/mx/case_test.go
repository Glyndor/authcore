package mx

import (
	"context"
	"net"
	"testing"
	"time"
)

// DNS names are case-insensitive, so the spellings of one domain are one
// query. Before, each spelling was its own cache key and its own lookup.
func TestVerifyDomain_spellingsOfOneDomainShareOneLookup(t *testing.T) {
	stub := newStub([]*net.MX{{Host: "mx.example.com."}}, nil)
	m := New(stub, time.Minute)

	for _, address := range []string{"a@example.com", "a@Example.com", "a@EXAMPLE.COM", "a@eXaMpLe.CoM"} {
		if err := m.Verify(context.Background(), address); err != nil {
			t.Fatalf("Verify(%q): %v", address, err)
		}
	}
	if got := stub.calls(); got != 1 {
		t.Errorf("four spellings of one domain made %d lookups, want 1", got)
	}
}

// Folding the whole Unicode range would turn U+212A KELVIN SIGN into "k" and
// U+0130 into "i", and the lookup would verify another domain than the one the
// caller wrote. Only ASCII letters fold.
func TestVerifyDomain_unicodeLookalikesAreNotFoldedOntoAsciiDomains(t *testing.T) {
	stub := newStub([]*net.MX{{Host: "mx.example."}}, nil)
	m := New(stub, time.Minute)

	for _, address := range []string{"u@kmail.com", "u@Kmail.com", "u@info.com", "u@İnfo.com"} {
		_ = m.Verify(context.Background(), address)
	}
	if got := stub.calls(); got != 4 {
		t.Errorf("four different domains made %d lookups, want 4", got)
	}
}
