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
//
// # What is tunable
//
// Memory, Iterations, and Parallelism can be increased to match your hardware.
// The algorithm and output format are never configurable — that's the point.
//
// # Rejecting breached passwords (opt-in)
//
// Length and composition rules keep out structurally weak passwords; they do
// not catch a strong-looking password that has already leaked in a public
// breach. Set Config.BreachChecker to enable an opt-in breach check via
// CheckBreached — off by default, so the module stays offline and zero-config:
//
//	cfg := password.DefaultConfig()
//	cfg.BreachChecker = password.NewHIBPChecker() // HaveIBeenPwned, k-anonymity
//	pwdMod, _ := password.New(auth, cfg)
//	if err := pwdMod.CheckBreached(ctx, userPassword); errors.Is(err, password.ErrBreachedPassword) {
//	    // ask the user for a different password
//	}
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
//	newHash, _ := pwdMod.Hash(newPassword)
//	db.UpdatePasswordHash(userID, newHash)
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/Glyndor/authcore"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	saltLen = 16 // bytes — 128 bits of entropy per hash
	keyLen  = 32 // bytes — 256-bit Argon2id output
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
	var resolved Config
	if len(cfg) > 0 {
		resolved = cfg[0]
	}
	resolved = applyDefaults(resolved) // fill any zero-value fields with safe defaults

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

// ValidatePolicy reports whether plaintext satisfies the built-in password policy.
// Use this for fail-fast validation before calling Hash — for example, in an HTTP
// handler to return a 400 before spending CPU on Argon2id.
//
// Returns nil if the password is acceptable, or [ErrWeakPassword] wrapping the
// specific rule that was violated. The wrapped reason is safe to show the user:
//
//	if err := pwdMod.ValidatePolicy(req.Password); err != nil {
//	    reason := errors.Unwrap(err).Error() // "must be at least 12 characters"
//	    c.JSON(400, gin.H{"error": reason})
//	}
//
// This check is identical to the one Hash performs internally.
func (p *Password) ValidatePolicy(plaintext string) error {
	if err := checkPolicy(norm.NFC.String(plaintext)); err != nil {
		return &policyViolation{reason: err}
	}
	return nil
}

// checkPolicy validates plaintext against the built-in password policy.
// It runs in O(n) with a single pass and no memory allocations.
//
// Rules:
//   - Length between 12 and 64 characters.
//   - At least one uppercase letter (Unicode-aware).
//   - At least one lowercase letter (Unicode-aware).
//   - At least one digit.
//   - At least one special character (anything that is not a letter or digit).
func checkPolicy(plaintext string) error {
	if len(plaintext) < 12 {
		return fmt.Errorf("must be at least 12 characters")
	}
	if len(plaintext) > 64 {
		return fmt.Errorf("must be at most 64 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range plaintext {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	switch {
	case !hasUpper:
		return fmt.Errorf("must contain at least one uppercase letter")
	case !hasLower:
		return fmt.Errorf("must contain at least one lowercase letter")
	case !hasDigit:
		return fmt.Errorf("must contain at least one digit")
	case !hasSpecial:
		return fmt.Errorf("must contain at least one special character")
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
// Policy (always enforced):
//   - 12–64 characters
//   - At least one uppercase letter, one lowercase letter, one digit, one special character
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
	if err := checkPolicy(plaintext); err != nil {
		return "", &policyViolation{reason: err}
	}

	// Fresh random salt per call ensures two hashes of the same password are
	// always different strings — prevents rainbow-table precomputation attacks.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	// Argon2id: memory-hard, GPU/ASIC-resistant. This deliberately allocates
	// ~Memory KiB of RAM to make brute-force attacks expensive.
	key := argon2.IDKey([]byte(plaintext), salt, p.cfg.Iterations, p.cfg.Memory, p.cfg.Parallelism, keyLen)

	// Encode as PHC string: self-describing and portable across libraries.
	// Embedding the parameters in the hash string means Verify can always
	// reconstruct the exact same hash without consulting the module config.
	// Salt and key are base64-encoded without padding (RFC 4648 §5).
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.cfg.Memory,
		p.cfg.Iterations,
		p.cfg.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
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
//   - Parallelism: ≥ 1
//
// The comparison is performed in constant time to prevent timing attacks.
//
// Returns ErrInvalidHash when phcHash is malformed, uses a non-Argon2id
// algorithm, or carries parameters outside the ranges above.
//
//	ok, err := pwdMod.Verify(submittedPassword, storedHash)
//	if errors.Is(err, password.ErrInvalidHash) { ... } // hash is malformed or out of range
//	if !ok { return http.StatusUnauthorized }
func (p *Password) Verify(plaintext, phcHash string) (bool, error) {
	// Normalise to Unicode NFC (matching Hash) so the user can sign in from a
	// different platform than the one they registered on without losing access
	// to their account.
	plaintext = norm.NFC.String(plaintext)

	// Extract the Argon2id parameters and salt embedded in the stored hash.
	// Using the stored parameters — not the current module config — means old
	// hashes remain valid even after the work factors are tuned upward.
	params, salt, storedKey, err := parsePHC(phcHash)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}

	// Recompute the derived key with the same parameters and salt as the original.
	key := argon2.IDKey([]byte(plaintext), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(storedKey)))

	// Compare in constant time to prevent timing attacks that could reveal
	// how many bytes of the candidate key matched the stored key.
	return subtle.ConstantTimeCompare(key, storedKey) == 1, nil
}

// parsePHC decodes a PHC string produced by Hash and returns the embedded
// Argon2id parameters, the decoded salt, and the decoded derived key.
func parsePHC(phcHash string) (Config, []byte, []byte, error) {
	// Expected: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
	// strings.Split on "$" produces: ["", "argon2id", "v=19", "m=...", "<salt>", "<key>"]
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return Config{}, nil, nil, fmt.Errorf("expected 6 dollar-separated segments, got %d", len(parts))
	}
	if parts[1] != "argon2id" {
		return Config{}, nil, nil, fmt.Errorf("unsupported algorithm %q, want argon2id", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Config{}, nil, nil, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return Config{}, nil, nil, fmt.Errorf("unsupported Argon2 version %d, want %d", version, argon2.Version)
	}

	var cfg Config
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cfg.Memory, &cfg.Iterations, &cfg.Parallelism); err != nil {
		return Config{}, nil, nil, fmt.Errorf("parse parameters: %w", err)
	}

	// Bound the parsed parameters before handing them to argon2.IDKey. A
	// corrupted or attacker-supplied hash with m=4_000_000_000 would otherwise
	// cause the verifier to attempt a multi-TiB allocation and crash the
	// process. Reuse the same ceilings validateConfig enforces at construction.
	if cfg.Memory < minMemory || cfg.Memory > maxMemory {
		return Config{}, nil, nil, fmt.Errorf("memory parameter out of range: got %d, want [%d, %d]", cfg.Memory, minMemory, maxMemory)
	}
	if cfg.Iterations < 1 || cfg.Iterations > maxIterations {
		return Config{}, nil, nil, fmt.Errorf("iterations parameter out of range: got %d, want [1, %d]", cfg.Iterations, maxIterations)
	}
	if cfg.Parallelism < 1 {
		return Config{}, nil, nil, fmt.Errorf("parallelism parameter out of range: got %d, want >= 1", cfg.Parallelism)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("decode key: %w", err)
	}

	return cfg, salt, key, nil
}
