// Package password provides Argon2id password hashing for authcore.
//
// # Why Argon2id?
//
// Argon2id is the algorithm recommended by OWASP and RFC 9106 for password
// storage. Unlike bcrypt, it is memory-hard: an attacker must allocate large
// amounts of RAM per attempt, making GPU and ASIC brute-force attacks
// prohibitively expensive.
//
// # Zero-config setup
//
// The OWASP-recommended defaults work out of the box — no configuration needed:
//
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	pwdMod, _ := password.New(auth) // ← that's it
//
// # What is fixed (security guarantees you get for free)
//
//   - Algorithm: Argon2id (RFC 9106) — always
//   - Salt: 16 random bytes per hash — via crypto/rand
//   - Key length: 32 bytes (256-bit output)
//   - Output: PHC string format — self-describing, portable
//   - Comparison: constant-time — immune to timing attacks
//   - Policy: Hash rejects weak passwords before spending CPU on them
//   - Printable input only: Hash refuses control, format and other
//     default-ignorable characters, and the blank braille pattern. Variation
//     selectors are accepted on purpose (emoji and some CJK characters carry
//     them) and are not folded: two passwords that render the same but differ
//     in a variation selector are different passwords.
//
// # What is tunable
//
// The cryptographic work factor (Memory, Iterations, Parallelism) and the
// policy (MinLength, MaxLength, RequireUpper, RequireLower, RequireDigit,
// RequireSymbol) can be raised or lowered to match your product. Defaults
// reproduce the policy the library has always enforced - see
// [Config]. The algorithm, salt size, key size, output format, and Unicode
// NFC normalisation are never configurable - that's the point.
//
// # Full usage
//
//	// Startup — one instance, shared across all goroutines.
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	pwdMod, _ := password.New(auth)
//
//	// Registration — hash and store. Never store the plaintext.
//	hash, err := pwdMod.Hash(userPassword)
//	db.StorePasswordHash(userID, hash)
//
//	// Login — verify in constant time.
//	ok, err := pwdMod.Verify(submittedPassword, storedHash)
//	if !ok { return http.StatusUnauthorized }
//
//	// Password change — verify first, then hash the new one.
//	ok, _ = pwdMod.Verify(currentPassword, storedHash)
//	if !ok { return http.StatusUnauthorized }
//	newHash, err := pwdMod.Hash(newPassword)
//	if err != nil { return err } // do not persist a failed result
//	db.UpdatePasswordHash(userID, newHash)
package password

import (
	"fmt"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password/internal/kdf"
)

// Compile-time assertion: *Password must satisfy authcore.Module.
var _ authcore.Module = (*Password)(nil)

// Password is the authentication module for Argon2id password hashing.
//
// Construct one instance at application startup using New and share it
// across goroutines. Password is safe for concurrent use after construction.
type Password struct {
	cfg Config
	log authcore.Logger
}

// New creates and returns a Password module.
//
// cfg is optional — omit it to use the OWASP-recommended defaults
// (Argon2id, 64 MiB, 3 iterations, 2 threads). Pass a Config only when
// you need to tune the work parameters for your hardware:
//
//	// zero-config — safe defaults, no boilerplate
//	pwdMod, err := password.New(auth)
//
//	// custom work factor for a more powerful server
//	pwdMod, err := password.New(auth, password.Config{
//	    Memory:      128 * 1024,
//	    Iterations:  4,
//	    Parallelism: 4,
//	})
func New(p authcore.Provider, cfg ...Config) (*Password, error) {
	// Accept an optional Config via variadic to allow zero-config usage:
	//   password.New(auth)             — OWASP defaults, no boilerplate
	//   password.New(auth, customCfg)  — custom work factors
	//
	// A nil provider or logger used to panic, and a second Config was dropped
	// without a word; #406 and #413 fixed that in four other modules and not
	// here (2026-09-25).
	if len(cfg) > 1 {
		return nil, fmt.Errorf("%w: at most one Config is allowed, got %d", ErrInvalidConfig, len(cfg))
	}
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	if p.Logger() == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	var resolved Config
	if len(cfg) > 0 {
		resolved = cfg[0]
	}
	resolved = applyDefaults(resolved) // fill any zero-value fields with safe defaults

	// Snapshot each *bool policy field into storage the caller does not hold a
	// pointer to. Without this, the module would read policy through the same
	// memory the caller still owns, so flipping *cfg.RequireSymbol = false after
	// New would silently change what an existing module accepts.
	resolved.RequireUpper = ptr(*resolved.RequireUpper)
	resolved.RequireLower = ptr(*resolved.RequireLower)
	resolved.RequireDigit = ptr(*resolved.RequireDigit)
	resolved.RequireSymbol = ptr(*resolved.RequireSymbol)

	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	pw := &Password{cfg: resolved, log: p.Logger()}

	pw.log.Info("password: module initialised (memory=%dKiB, iterations=%d, parallelism=%d)",
		resolved.Memory, resolved.Iterations, resolved.Parallelism)

	return pw, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (p *Password) Name() string { return "password" }

// ValidatePolicy reports whether plaintext satisfies the configured password policy.
// Use this for fail-fast validation before calling Hash — for example, in an HTTP
// handler to return a 400 before spending CPU on Argon2id.
//
// Returns nil if the password is acceptable, or [ErrWeakPassword] wrapping the
// specific rule that was violated. The wrapped reason is safe to show the user:
//
//	if err := pwdMod.ValidatePolicy(req.Password); err != nil {
//	    reason := errors.Unwrap(err).Error() // e.g. "must be at least 16 characters"
//	    c.JSON(400, gin.H{"error": reason})
//	}
//
// This check is identical to the one Hash performs internally. The bounds and
// required classes it enforces come from the module's Config (see
// [Config.MinLength], [Config.MaxLength] and the [Config.RequireUpper] family),
// so the message reflects what the caller actually configured. One rule is not
// configurable: characters must be printable. Length is checked first after
// NFC normalization, so a length violation supplies the wrapped reason even
// when the input contains a non-printable character. Once length passes, the
// printable-character check precedes the required classes and uses
// [ErrNonPrintableCharacter] as its wrapped reason.
func (p *Password) ValidatePolicy(plaintext string) error {
	if err := checkPolicy(norm.NFC.String(plaintext), p.cfg); err != nil {
		return &policyViolation{reason: err}
	}
	return nil
}

// Hash validates plaintext against the built-in password policy and, if it
// passes, derives an Argon2id hash returned in PHC string format. A fresh
// cryptographically random salt is generated per call, so two calls with the
// same input produce different (but equivalent) hashes.
//
// plaintext is normalised to Unicode NFC before policy checks and hashing,
// so the same visual password typed on different platforms (precomposed vs
// decomposed accents) produces the same hash. Users who register on one
// operating system and sign in on another are not locked out.
//
// Policy with the default Config:
//   - 12–64 characters
//   - At least one uppercase letter, one lowercase letter, one digit, one special character
//
// A special character is Unicode punctuation, a Unicode symbol, or the ASCII
// space. A printable character outside the four classes, such as a letter
// without case, is accepted and satisfies none of them.
//
// Under every Config, a plaintext holding a character that is not printable
// (control, invisible format, non-ASCII space, unassigned, or invalid UTF-8)
// is refused. Length is checked first after NFC normalization, so a length
// violation supplies the reason wrapped in [ErrWeakPassword]. Once length
// passes, the printable-character check precedes the required classes and
// returns [ErrNonPrintableCharacter] wrapped in [ErrWeakPassword] on failure.
// Verify applies no policy, so a hash stored before this rule existed keeps
// verifying against the password it was made from.
//
// Store the returned string in your database. Never store the plaintext password.
//
//	hash, err := pwdMod.Hash(userPassword)
//	if errors.Is(err, password.ErrWeakPassword) { /* tell the user what's wrong */ }
//	db.StorePasswordHash(userID, hash)
func (p *Password) Hash(plaintext string) (string, error) {
	// Normalise to Unicode NFC so the same visual password typed on different
	// systems (precomposed vs combining accents, e.g. "café" as one codepoint
	// vs "e" + combining-acute) produces the same hash. Without this, users
	// who register on one platform and sign in on another can be locked out.
	plaintext = norm.NFC.String(plaintext)

	// Validate before hashing — fail fast before spending ~64 MiB of RAM on Argon2id.
	if err := checkPolicy(plaintext, p.cfg); err != nil {
		return "", &policyViolation{reason: err}
	}

	return kdf.Hash(plaintext, p.cfg.phcParams())
}

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
func (p *Password) Verify(plaintext, phcHash string) (bool, error) {
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
