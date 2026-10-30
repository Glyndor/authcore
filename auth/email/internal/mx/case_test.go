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
