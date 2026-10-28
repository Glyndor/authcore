package memory_test

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a provider, or anyone able to hand the callback a string, that
// sends an ID token made of thousands of tiny claims. A real token is a few
// claims; the verifier reads at most a bounded number of bytes of it, so the
// price of a flood is a bounded multiple of the token, measured here against
// the price of an ordinary token verified by the same warm client.

// flood returns the claim set of an ordinary token plus n one-digit claims.
func flood(n int) map[string]any {
	over := make(map[string]any, n)
	for i := range n {
		over[fmt.Sprintf("c%d", i)] = 1
	}
	return hostiletest.Claims(hostiletest.Nonce, over)
}

func TestHostile_Memory_aFloodOfClaimsCostsABoundedMultipleOfTheToken(t *testing.T) {
	c, _ := hostiletest.JWKSClient(t, hostiletest.StdJWKS(t))
	ordinary := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))
	if _, err := hostiletest.Verify(t, c, ordinary); err != nil { // warms the key cache
		t.Fatalf("control: an ordinary token was refused: %v", err)
	}
	base, _ := allocOf(func() { _, _ = hostiletest.Verify(t, c, ordinary) })

	cases := []struct {
		name   string
		claims int
		// perByte is the allocation allowed per byte of token, over the cost
		// of an ordinary token. Measured on 2026-10-28 at 18 for a token that
		// fits the cap, and the bound is 3x that. A token over the cap is
		// refused on its length, so it costs no more than an ordinary one.
		perByte uint64
	}{
		{"as many claims as fit under the size cap", 1100, 60},
		{"far more claims than fit under the size cap", 40000, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := hostiletest.SignA(t, flood(tc.claims))
			got, _ := allocOf(func() { _, _ = hostiletest.Verify(t, c, token) })
			if limit := 4*base + uint64(len(token))*tc.perByte; got > limit {
				t.Fatalf("a %d-byte token of %d claims allocated %d bytes, over %d (an ordinary token: %d)", len(token), tc.claims, got, limit, base)
			}
		})
	}
}
