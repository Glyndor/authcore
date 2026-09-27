package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The oracle for these tests is the forgery itself, independent of how
// checkVerificationKey decides: a key is dangerous when crypto/ed25519
// accepts the signature (R = identity, S = 0) for some message under it.

var forgedSignature = append([]byte{0x01}, make([]byte, ed25519.SignatureSize-1)...)

// forgeable reports whether crypto/ed25519 accepts the all-but-free signature
// for at least one of 64 messages under pub.
func forgeable(pub ed25519.PublicKey) bool {
	for i := range 64 {
		if ed25519.Verify(pub, []byte(fmt.Sprintf("message %d", i)), forgedSignature) {
			return true
		}
	}
	return false
}

// encoding returns the 32-byte little-endian encoding with first as its
// lowest byte, fill for the next thirty bytes and last as its highest byte.
func encoding(first, fill, last byte) ed25519.PublicKey {
	k := bytes.Repeat([]byte{fill}, ed25519.PublicKeySize)
	k[0], k[31] = first, last
	return k
}

var orderEight = []ed25519.PublicKey{
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
}

func TestCheckVerificationKey_refusesTheForgeableKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		key    ed25519.PublicKey
		reason string
	}{
		"all zero, order 4":             {encoding(0x00, 0x00, 0x00), "small order"},
		"all zero with the sign bit":    {encoding(0x00, 0x00, 0x80), "small order"},
		"the identity":                  {encoding(0x01, 0x00, 0x00), "identity"},
		"y = p-1, order 2":              {encoding(0xec, 0xff, 0x7f), "small order"},
		"y = p, a second zero":          {encoding(0xed, 0xff, 0x7f), "not a canonical encoding"},
		"y = p+1, a second identity":    {encoding(0xee, 0xff, 0x7f), "not a canonical encoding"},
		"y = 2^255-1, past the modulus": {encoding(0xff, 0xff, 0x7f), "not a canonical encoding"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkVerificationKey(tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("checkVerificationKey = %v, want a refusal naming %q", err, tc.reason)
			}
		})
	}
	// The two points of order 8, as libsodium's small-order blocklist encodes
	// them. The oracle below confirms they really are small-order before the
	// refusal is believed.
	for _, k := range orderEight {
		if err := checkVerificationKey(k); err == nil || !strings.Contains(err.Error(), "small order") {
			t.Fatalf("order-8 key %x: %v, want the small-order refusal", k, err)
		}
	}
	// The oracle agrees on the canonical small-order keys: each one really
	// lets the free signature through.
	for _, k := range append([]ed25519.PublicKey{encoding(0x00, 0x00, 0x00), encoding(0x01, 0x00, 0x00), encoding(0xec, 0xff, 0x7f)}, orderEight...) {
		if !forgeable(k) {
			t.Fatalf("the oracle does not forge under %x; the test would prove nothing", k)
		}
	}
}

// The acceptance side: real keys pass, and the oracle cannot forge under them.
func TestCheckVerificationKey_acceptsGeneratedKeys(t *testing.T) {
	for i := range 200 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkVerificationKey(pub); err != nil {
			t.Fatalf("generated key %d refused: %v", i, err)
		}
		if i < 5 && forgeable(pub) {
			t.Fatalf("the oracle forges under a generated key %x", pub)
		}
	}
}

func TestNew_refusesAForgeablePreviousKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{encoding(0x00, 0x00, 0x00)}
	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "previous public key 0 cannot be trusted") {
		t.Fatalf("New with the all-zero previous key = %v, want ErrInvalidConfig naming the key", err)
	}

	cfg.PreviousPublicKeys = []ed25519.PublicKey{newFakeProvider(t).Keys().PublicKey()}
	if _, err := New[struct{}](newFakeProvider(t), cfg); err != nil {
		t.Fatalf("New with a real previous key = %v, want accepted", err)
	}
}
