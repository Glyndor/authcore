// Package kdf derives and checks Argon2id password hashes in PHC string form.
//
// It owns the key derivation only: Unicode normalisation and the password
// policy belong to the password package, which hands plaintext over already
// normalised. The PHC format lives in internal/phc.
package kdf

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// Hash derives an Argon2id hash of plaintext with the cost parameters in p and
// a fresh cryptographically random salt, and returns it as a PHC string. Two
// calls with the same input produce different (but equivalent) hashes.
//
// plaintext must already be NFC-normalised and policy-checked.
func Hash(plaintext string, p phc.Params) (string, error) {
	// Fresh random salt per call ensures two hashes of the same password are
	// always different strings — prevents rainbow-table precomputation attacks.
	salt := make([]byte, phc.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	// Argon2id: memory-hard, GPU/ASIC-resistant. This deliberately allocates
	// ~Memory KiB of RAM to make brute-force attacks expensive.
	key := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.Memory, p.Parallelism, phc.KeyLen)

	// Encode as PHC string: self-describing and portable across libraries.
	// Embedding the parameters in the hash string means Verify can always
	// reconstruct the exact same hash without consulting the module config.
	// Salt and key are base64-encoded without padding (RFC 4648 §5).
	return phc.Encode(p, salt, key), nil
}

// Verify reports whether plaintext matches the Argon2id hash in phcHash. The
// cost parameters are read from phcHash itself, bounded by phc.Parse and then
// by ceiling, so a stored hash cannot force an unbounded allocation or run
// time. The returned error wraps phc.ErrInvalid when phcHash is malformed or
// out of range, when any of its parameters is above ceiling, and when
// Memory x Iterations (in KiB-passes) is above maxWork; in that case no key is
// derived.
//
// plaintext must already be NFC-normalised.
func Verify(plaintext, phcHash string, ceiling phc.Params, maxWork uint64) (bool, error) {
	// Extract the Argon2id parameters and salt embedded in the stored hash.
	// Using the stored parameters — not the current module config — means old
	// hashes remain valid even after the work factors are tuned upward.
	params, salt, storedKey, err := phc.Parse(phcHash)
	if err != nil {
		return false, err
	}

	if params.Memory > ceiling.Memory || params.Iterations > ceiling.Iterations || params.Parallelism > ceiling.Parallelism {
		return false, fmt.Errorf("%w: cost parameters exceed the ceiling the module accepts", phc.ErrInvalid)
	}

	// The factors can each sit under their ceiling and still multiply into a
	// hash that pins a core for tens of seconds.
	if uint64(params.Memory)*uint64(params.Iterations) > maxWork {
		return false, fmt.Errorf("%w: memory x iterations exceeds the work the module accepts", phc.ErrInvalid)
	}

	// Recompute the derived key with the same parameters and salt as the original.
	key := argon2.IDKey([]byte(plaintext), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(storedKey)))

	// Compare in constant time to prevent timing attacks that could reveal
	// how many bytes of the candidate key matched the stored key.
	return subtle.ConstantTimeCompare(key, storedKey) == 1, nil
}
