package jwk_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
)

func TestParseAcceptsAnOnCurvePointWithZeroX(t *testing.T) {
	t.Parallel()
	// For P-256 at x=0, y is a square root of the curve coefficient B.
	// This point has prime order like every finite point on this curve.
	key, err := jwk.Parse(jwk.JWK{
		Kty: "EC", Crv: "P-256", X: "AA",
		Y: "ZkhceA4vg9ckM71dhKBrtlQcKvMdrocXKL-FahdPk_Q",
	})
	if err != nil {
		t.Fatalf("on-curve point with x=0 was refused: %v", err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.X.Sign() != 0 || pub.Y.Text(16) != "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4" {
		t.Fatalf("parsed point changed: %v", key)
	}
}
