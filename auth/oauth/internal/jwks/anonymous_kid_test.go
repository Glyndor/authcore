package jwks

import (
	"context"
	"errors"
	"testing"
)

// A key published without a kid answers only a token that carries no kid. A
// token naming some kid must not be verified against the one kid-less key just
// because it is the only key there is.
func TestJWKS_aNamedKidDoesNotFallBackToTheOnlyKidlessKey(t *testing.T) {
	signer := mustGenRSA(t)
	srv := serveJWKS(t, rsaJWKWith(t, &signer.PublicKey, "", "", "", nil))
	cache := newCache(srv, fakeNow())

	_, err := cache.Key(context.Background(), "attacker-chosen", "RS256")
	if err == nil {
		t.Fatal("a token naming a kid the JWKS does not list must be refused")
	}
	if !errors.Is(err, ErrJWKS) {
		t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
	}
	// Control: the same cache serves the kid-less token.
	if _, err := cache.Key(context.Background(), "", "RS256"); err != nil {
		t.Fatalf("a kid-less token must verify against the kid-less key: %v", err)
	}
}
