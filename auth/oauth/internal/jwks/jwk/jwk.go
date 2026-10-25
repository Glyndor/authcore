// Package jwk parses a single JSON Web Key into an RSA or EC public key, bounding key sizes and
// coordinates.
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// JWK is one JSON Web Key. The fields that restrict the key (alg, use,
// key_ops) are kept here and enforced at selection time per RFC 7517 §4.3 and
// RFC 8725 §3.1.
type JWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"` // RSA modulus (base64url)
	E      string   `json:"e"` // RSA exponent (base64url)
	Crv    string   `json:"crv"`
	X      string   `json:"x"` // EC x (base64url)
	Y      string   `json:"y"` // EC y (base64url)
	// Issuer restricts the key to tokens from one issuer. Microsoft publishes
	// it on every key of its common JWKS, some pinned to one tenant and some
	// holding the "{tenantid}" template, and tells multi-tenant clients to
	// enforce it. It is not an RFC 7517 member; other providers omit it.
	Issuer string `json:"issuer"`
}

// Parse converts a JWK into an RSA or EC public key.
func Parse(k JWK) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64BigInt(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eBytes)
		// Bound the exponent to 31 bits: it must fit an int on a 32-bit build
		// (int(e.Int64()) would otherwise silently truncate), and a real RSA
		// exponent is tiny (commonly 65537).
		if !e.IsInt64() || e.Int64() < 2 || e.BitLen() > 31 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		// Bound the modulus: reject undersized (potentially factorable) keys, and
		// cap the upper end so a hostile JWKS cannot publish a multi-megabit
		// modulus that turns every verification into a heavy modexp (CPU DoS).
		if bits := n.BitLen(); bits < 2048 || bits > 16384 {
			return nil, fmt.Errorf("RSA modulus out of range: %d bits", bits)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64BigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64BigInt(k.Y)
		if err != nil {
			return nil, err
		}
		// Bound the coordinates to the field size before calling FillBytes:
		// big.Int.FillBytes panics when the value does not fit the buffer,
		// and a malformed JWKS could carry integers wider than the field.
		size := (curve.Params().BitSize + 7) / 8
		if x.Sign() < 0 || y.Sign() < 0 || len(x.Bytes()) > size || len(y.Bytes()) > size {
			return nil, fmt.Errorf("EC coordinate out of range")
		}
		buf := make([]byte, 1+2*size)
		buf[0] = 4 // uncompressed point per SEC 1 §2.3.3
		x.FillBytes(buf[1 : 1+size])
		y.FillBytes(buf[1+size:])
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, buf)
		if err != nil {
			return nil, fmt.Errorf("EC point is not on curve: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type %s", safetext.Quote(k.Kty))
	}
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %s", safetext.Quote(crv))
	}
}

// b64BigInt decodes a base64url (no padding) big-endian unsigned integer.
func b64BigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
