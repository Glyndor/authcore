package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
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
	if !ok {
		t.Fatalf("parsed key is %T, want *ecdsa.PublicKey", key)
	}
	// Bytes is the uncompressed point: 0x04, then X and Y as 32 bytes each.
	point, err := pub.Bytes()
	if err != nil {
		t.Fatalf("parsed point cannot be encoded: %v", err)
	}
	if len(point) != 65 || !bytes.Equal(point[1:33], make([]byte, 32)) ||
		hex.EncodeToString(point[33:]) != "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4" {
		t.Fatalf("parsed point changed: %x", point)
	}
}
