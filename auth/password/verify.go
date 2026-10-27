package password

import (
	"fmt"

	"github.com/Glyndor/authcore/auth/password/internal/kdf"
	"golang.org/x/text/unicode/norm"
)

// maxVerifyInputBytes is independent of the active password policy. The global
// 1024-rune policy ceiling times the normalization segment buffer size leaves
// room for decomposed Unicode and historical passwords while bounding input
// before NFC and Argon2. Oversized credentials use the existing early-refusal
// pattern for inputs that never reach key derivation.
const maxVerifyInputBytes = maxPolicyLength * norm.MaxSegmentSize

// Verify reports whether plaintext matches the Argon2id hash in phcHash.
//
// The Argon2id parameters (Memory, Iterations, Parallelism) are read from
// phcHash itself, so stored hashes remain valid even if the module's Config
// is updated after they were created. The parsed parameters are bounded to
// the same ceilings validateConfig enforces at construction, so a corrupted
// or malicious stored hash cannot force argon2.IDKey into an unbounded
// memory allocation.
//
// Supported parameter ranges (mirroring Config validation):
//   - Memory:      8 MiB – 4 GiB (8192 – 4194304 KiB)
//   - Iterations:  1 – 20
//   - Parallelism: 1 – 255
//   - Salt:        exactly 16 bytes
//   - Key:         exactly 32 bytes
//
// The comparison is performed in constant time to prevent timing attacks.
// Plaintext above 128 KiB returns false, nil before normalization or key
// derivation, independently of Config.MaxLength and phcHash. This resource
// refusal follows the early-return pattern used for invalid hashes; calls
// that derive a key retain their existing constant-time comparison.
//
// Returns ErrInvalidHash when phcHash is malformed, uses a non-Argon2id
// algorithm, or carries parameters or salt/key lengths outside the ranges
// above, or when any of Memory, Iterations and Parallelism is higher than the
// module accepts: 128 times the configured Memory (at most 1 GiB, or the
// configured Memory when that is larger), and 8 times the configured Iterations
// and Parallelism, and when Memory times Iterations is above 4 GiB-passes (or
// the configured product when that is larger). A hash above that is refused
// before any key is derived. A truncated hash never reaches the KDF, so it can neither verify
// true nor crash the process.
//
//	ok, err := pwdMod.Verify(submittedPassword, storedHash)
//	if errors.Is(err, password.ErrInvalidHash) { ... } // hash is malformed or out of range
//	if !ok { return http.StatusUnauthorized }
//
// On a nil or zero-value Password it returns an error wrapping ErrInvalidConfig.
func (p *Password) Verify(plaintext, phcHash string) (bool, error) {
	if !p.built() {
		return false, errNotBuilt
	}
	if len(plaintext) > maxVerifyInputBytes {
		return false, nil
	}
	// Normalise to Unicode NFC (matching Hash) so the user can sign in from a
	// different platform than the one they registered on without losing access
	// to their account.
	plaintext = norm.NFC.String(plaintext)

	ok, err := kdf.Verify(plaintext, phcHash, p.cfg.verifyCeiling(), p.cfg.verifyWorkCeiling())
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidHash, invalidHash{cause: err})
	}
	return ok, nil
}
