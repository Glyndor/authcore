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
//   - Printable input only: Hash refuses control and invisible characters
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
	"unicode/utf8"

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
// configurable: a character that is not printable is refused with
// [ErrNonPrintableCharacter] as the wrapped reason.
func (p *Password) ValidatePolicy(plaintext string) error {
	if err := checkPolicy(norm.NFC.String(plaintext), p.cfg); err != nil {
		return &policyViolation{reason: err}
	}
	return nil
}

// checkPolicy validates plaintext against the policy encoded in cfg.
// It runs in O(n) with a single pass and no memory allocations.
//
// Length is measured in Unicode characters (runes), not bytes, so a
// multibyte passphrase is counted the way a user perceives it: a 4-character
// CJK password is 4 characters, not 12 bytes.
//
// The cfg argument must already have its *bool policy fields resolved
// (applyDefaults guarantees non-nil), so this function reads them through
// the pointer without nil checks. The error messages quote cfg.MinLength
// and cfg.MaxLength, so the caller sees the bound they actually configured.
//
// Keep the printable check ahead of the classification and outside cfg. It is
// not a product rule a caller can turn off: until #347 a NUL appended to
// "Abcdefghijk1" was what made it pass, got hashed, and verified.
func checkPolicy(plaintext string, cfg Config) error {
	count := utf8.RuneCountInString(plaintext)
	if count < cfg.MinLength {
		return fmt.Errorf("must be at least %d characters", cfg.MinLength)
	}
	if count > cfg.MaxLength {
		return fmt.Errorf("must be at most %d characters", cfg.MaxLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range plaintext {
		if !isPrintable(r) {
			return ErrNonPrintableCharacter
		}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case isSpecial(r):
			hasSpecial = true
		}
		// No default arm on purpose. A printable rune outside the four classes
		// (a letter without case such as a CJK ideograph, a combining mark, a
		// number that is not a decimal digit) is allowed and satisfies nothing.
	}

	switch {
	case *cfg.RequireUpper && !hasUpper:
		return fmt.Errorf("must contain at least one uppercase letter")
	case *cfg.RequireLower && !hasLower:
		return fmt.Errorf("must contain at least one lowercase letter")
	case *cfg.RequireDigit && !hasDigit:
		return fmt.Errorf("must contain at least one digit")
	case *cfg.RequireSymbol && !hasSpecial:
		return fmt.Errorf("must contain at least one special character")
	}
	return nil
}

// isPrintable reports whether r may appear in a password at all.
//
// unicode.IsPrint is true for letters, marks, numbers, punctuation, symbols
// and the ASCII space, and false for control characters, format characters
// such as the zero-width joiner, every other space, and unassigned code
// points.
//
// U+FFFD needs its own clause. It is category So, so IsPrint accepts it, and
// it is what range yields for a byte that is not valid UTF-8. Measured before
// this check existed: "Abcdefghijk1\xff" passed the default policy with the
// stray byte counted as its special character.
func isPrintable(r rune) bool {
	return r != utf8.RuneError && unicode.IsPrint(r)
}

// isSpecial reports whether r satisfies RequireSymbol: Unicode punctuation
// (category P), Unicode symbols (category S), and the ASCII space.
//
// The space stays in the class because it always counted, OWASP lists it
// among the password special characters, and dropping it would start
// rejecting passphrases written as spaced words.
func isSpecial(r rune) bool {
	return r == ' ' || unicode.IsPunct(r) || unicode.IsSymbol(r)
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
// is refused with [ErrNonPrintableCharacter] wrapped in [ErrWeakPassword].
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
//   - Salt:        exactly 16 bytes
//   - Key:         exactly 32 bytes
//
// The comparison is performed in constant time to prevent timing attacks.
//
// Returns ErrInvalidHash when phcHash is malformed, uses a non-Argon2id
// algorithm, or carries parameters or salt/key lengths outside the ranges
// above. A truncated hash never reaches the KDF, so it can neither verify
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

	// Reject hashes whose salt or key are not the fixed sizes Hash produces.
	// A truncated hash with an empty key segment would otherwise reach
	// argon2.IDKey with keyLen=0, which panics (nil dereference) and crashes
	// the process. Enforcing the exact lengths fails closed on any corrupted
	// or attacker-supplied PHC string before it can reach the KDF.
	if len(salt) != saltLen {
		return Config{}, nil, nil, fmt.Errorf("salt has wrong length: got %d bytes, want %d", len(salt), saltLen)
	}
	if len(key) != keyLen {
		return Config{}, nil, nil, fmt.Errorf("derived key has wrong length: got %d bytes, want %d", len(key), keyLen)
	}

	return cfg, salt, key, nil
}
