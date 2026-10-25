package material

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// MinDistinctBytes is the fewest different byte values a 32-byte secret or
// seed may hold. Uniformly random 32 bytes hold about 30 different values; the
// chance that they hold 11 or fewer is about 6e-26 (below 2^-80), so a value
// the library or any sound generator produced is never refused, while the
// constant, repeating and counting values a broken provisioning script writes
// are. Raising it would start to refuse honest random material.
const MinDistinctBytes = 12

// degenerate names why b cannot be random-looking material, or returns "".
func degenerate(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	if constantStride(b) {
		return "its bytes are constant or form a counting sequence"
	}
	for p := 2; p <= len(b)/2; p++ {
		if repeatsWithPeriod(b, p) {
			return "it is one short block repeated"
		}
	}
	var seen [256]bool
	distinct := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	if distinct < MinDistinctBytes {
		return "it holds too few different byte values"
	}
	return ""
}

// constantStride reports whether every byte follows the previous one by the
// same step modulo 256: all equal (step 0), ascending or descending.
func constantStride(b []byte) bool {
	step := b[1] - b[0]
	for i := 2; i < len(b); i++ {
		if b[i]-b[i-1] != step {
			return false
		}
	}
	return true
}

// repeatsWithPeriod reports whether b[i] == b[i+p] for every i: b is a block
// of p bytes repeated, the last copy possibly cut short.
func repeatsWithPeriod(b []byte, p int) bool {
	for i := 0; i+p < len(b); i++ {
		if b[i] != b[i+p] {
			return false
		}
	}
	return true
}

// CheckSecret refuses a refresh secret that is not random-looking. The error
// names the rule and never contains the bytes.
func CheckSecret(secret []byte) error {
	if why := degenerate(secret); why != "" {
		return refusals.DegenerateMaterial("refresh secret", why)
	}
	return nil
}

// CheckSeed refuses an Ed25519 private key whose seed is not random-looking.
// The caller has already checked the key has the right length.
func CheckSeed(priv ed25519.PrivateKey) error {
	if why := degenerate(priv.Seed()); why != "" {
		return refusals.DegenerateMaterial("signing key seed", why)
	}
	return nil
}
