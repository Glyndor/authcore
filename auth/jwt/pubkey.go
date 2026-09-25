package jwt

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"math/big"
)

// fieldPrime is 2^255 - 19, the prime of the field Ed25519 points live in.
var fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// x25519Probe is a fixed X25519 scalar used only to test whether a point has
// small order. Any scalar works: X25519 clamps it to a multiple of 8, which
// sends every point of order 1, 2, 4 or 8 to the identity.
var x25519Probe = func() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey([]byte("authcore small-order probe key!!"))
	if err != nil {
		panic(err) // 32 bytes is always a valid X25519 scalar
	}
	return k
}()

// checkVerificationKey refuses an Ed25519 public key that would let anyone
// produce signatures it accepts, or that is not a canonical encoding.
//
// crypto/ed25519 verifies with the cofactorless equation and does not refuse
// small-order keys. For such a key the signature (R = identity, S = 0)
// verifies for every message whose challenge is a multiple of the key's
// order: always for the identity, one message in four for the all-zero key.
// A key listed in PreviousPublicKeys was trusted after checking its length
// alone, so a zero-filled [32]byte let anyone forge tokens under its kid
// until 2026-09-25.
func checkVerificationKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("wrong length")
	}
	// The encoding is y in little endian, with the sign of x in the top bit.
	le := make([]byte, len(pub))
	copy(le, pub)
	le[31] &= 0x7f
	y := new(big.Int).SetBytes(reversed(le))
	if y.Cmp(fieldPrime) >= 0 {
		return errors.New("not a canonical encoding")
	}

	// The Edwards point maps to the Montgomery u = (1+y)/(1-y). y = 1 is the
	// identity, whose u is undefined; every other small-order point maps to
	// a u that X25519 turns into the all-zero output, which ecdh refuses.
	oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
	oneMinusY.Mod(oneMinusY, fieldPrime)
	if oneMinusY.Sign() == 0 {
		return errors.New("the identity point")
	}
	u := new(big.Int).Add(big.NewInt(1), y)
	u.Mul(u, new(big.Int).ModInverse(oneMinusY, fieldPrime))
	u.Mod(u, fieldPrime)

	uBytes := make([]byte, 32)
	u.FillBytes(uBytes)
	peer, err := ecdh.X25519().NewPublicKey(reversed(uBytes))
	if err != nil {
		return errors.New("not a usable point")
	}
	if _, err := x25519Probe.ECDH(peer); err != nil {
		return errors.New("a point of small order")
	}
	return nil
}

// reversed returns a reversed copy of b, converting between the little-endian
// encodings of Ed25519 and X25519 and big.Int's big-endian bytes.
func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
