package password

import "fmt"

// Config holds the password module configuration.
//
// The configuration is split into two layers:
//
//   - The cryptographic work factor: Memory, Iterations, Parallelism.
//     Tunable so each deployment can match its own hardware budget.
//   - The policy layer: MinLength, MaxLength, RequireUpper, RequireLower,
//     RequireDigit, RequireSymbol. These are a product rule (how forgiving
//     your product wants to be), not cryptography - they exist so different
//     installations can express different minimum-strength requirements
//     while sharing the same Argon2id primitive. Defaults reproduce today's
//     behaviour exactly.
//
// What stays fixed regardless of configuration:
//
//   - Algorithm: Argon2id (RFC 9106) - always
//   - Salt: 16 random bytes per hash
//   - Key length: 32 bytes (256-bit output)
//   - Output format: PHC string (self-describing, portable)
//   - Comparison: constant-time
//
// Start from DefaultConfig and override only what your installation needs:
//
//	cfg := password.DefaultConfig()
//	cfg.Memory      = 128 * 1024  // 128 MiB — for a dedicated auth server
//	cfg.Iterations  = 4
//	cfg.Parallelism = 4           // match your guaranteed CPU core count
//	cfg.MinLength   = 16          // stricter length floor for your product
//	pwdMod, err := password.New(auth, cfg)
type Config struct {
	// Memory is the amount of memory used by Argon2id, in kibibytes.
	// Higher values increase resistance to GPU/ASIC brute-force attacks.
	// Defaults to 65536 (64 MiB). Minimum 8192 (8 MiB). Maximum 4194304 (4 GiB).
	Memory uint32

	// Iterations is the number of passes Argon2id makes over the memory.
	// Higher values increase the CPU cost per hash without changing memory use.
	// Defaults to 3. Minimum 1. Maximum 20.
	Iterations uint32

	// Parallelism is the number of threads Argon2id uses.
	// Set this to the minimum number of CPU cores guaranteed to your service.
	// Defaults to 2. Minimum 1.
	Parallelism uint8

	// MinLength is the minimum acceptable password length in runes.
	// Defaults to 12. Minimum 8 (anything below that is a weakened default
	// and is refused by validateConfig).
	MinLength int

	// MaxLength is the maximum acceptable password length in runes.
	// Defaults to 64. Capped at 1024 - Argon2id hashes the whole input, so
	// an unbounded maximum is a CPU denial-of-service: a single oversized
	// input can pin a hashing thread for several seconds.
	MaxLength int

	// RequireUpper requires at least one uppercase letter (Unicode-aware).
	// The pointer lets the caller express three states: nil means "keep
	// today's default (true)"; an explicit *p = false turns the class off.
	// A plain bool cannot distinguish "unset" from "deliberately false",
	// which is exactly the ambiguity this Config avoids.
	RequireUpper *bool

	// RequireLower requires at least one lowercase letter (Unicode-aware).
	// Pointer semantics: see RequireUpper.
	RequireLower *bool

	// RequireDigit requires at least one decimal digit.
	// Pointer semantics: see RequireUpper.
	RequireDigit *bool

	// RequireSymbol requires at least one special character: Unicode
	// punctuation, a Unicode symbol, or the ASCII space. A letter without
	// case, a combining mark and a non-decimal number do not count, and a
	// character that is not printable is refused whatever this field says
	// (see ErrNonPrintableCharacter).
	// Pointer semantics: see RequireUpper.
	RequireSymbol *bool
}

// DefaultConfig returns a Config with the library's recommended defaults.
//
// The cryptographic defaults are calibrated for a server with at least 2
// vCPUs and 4 GiB of RAM. The policy defaults reproduce today's built-in
// policy: 12–64 characters and one of each class (upper, lower, digit,
// symbol). Each Hash call temporarily allocates Memory kibibytes (64 MiB)
// of RAM. Tune Memory and Iterations upward on more capable hardware to
// strengthen the work factor over time, and MinLength upward if your
// product demands stricter passwords.
func DefaultConfig() Config {
	return Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		MinLength:   12,
		MaxLength:   64,
		// Pointer to true: a nil means "keep today's behaviour", and today's
		// behaviour is "require the class". An explicit false turns a class
		// off - see RequireUpper on the Config type for the rationale.
		RequireUpper:  ptr(true),
		RequireLower:  ptr(true),
		RequireDigit:  ptr(true),
		RequireSymbol: ptr(true),
	}
}

// ptr is a tiny helper so DefaultConfig can take the address of a true
// literal without a temporary local. It is intentionally unexported.
func ptr[T any](v T) *T { return &v }

// Bool returns a pointer to v, for setting the *bool policy fields on Config.
//
// The policy fields are pointers so that leaving one unset ("keep today's
// behaviour") is distinguishable from setting it to false ("turn this class
// off"). A plain bool cannot express both. Without this helper the caller
// needs a temporary local just to take its address, so the field is present
// but awkward to reach:
//
//	off := false
//	cfg.RequireSymbol = &off
//
// With it, turning a class off is one line:
//
//	cfg := password.DefaultConfig()
//	cfg.RequireSymbol = password.Bool(false)  // no symbol required
//	cfg.MinLength = 16                        // but a longer passphrase is
//	pwdMod, err := password.New(auth, cfg)
//
// Passing true is the same as leaving the field nil, and is accepted so a
// caller building a Config field by field can be explicit about every rule.
func Bool(v bool) *bool { return &v }

// applyDefaults fills zero-value fields with values from DefaultConfig.
// For the *bool policy fields, nil is treated the same as unset and filled
// with a pointer to true so that the rest of the package can read the value
// through the pointer without nil checks.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.Memory == 0 {
		cfg.Memory = def.Memory
	}
	if cfg.Iterations == 0 {
		cfg.Iterations = def.Iterations
	}
	if cfg.Parallelism == 0 {
		cfg.Parallelism = def.Parallelism
	}
	if cfg.MinLength == 0 {
		cfg.MinLength = def.MinLength
	}
	if cfg.MaxLength == 0 {
		cfg.MaxLength = def.MaxLength
	}
	if cfg.RequireUpper == nil {
		cfg.RequireUpper = def.RequireUpper
	}
	if cfg.RequireLower == nil {
		cfg.RequireLower = def.RequireLower
	}
	if cfg.RequireDigit == nil {
		cfg.RequireDigit = def.RequireDigit
	}
	if cfg.RequireSymbol == nil {
		cfg.RequireSymbol = def.RequireSymbol
	}
	return cfg
}

const (
	minMemory     = 8 * 1024        // 8 MiB in KiB
	maxMemory     = 4 * 1024 * 1024 // 4 GiB in KiB — prevents accidental DoS
	maxIterations = 20              // beyond this, hashing takes tens of seconds

	// minPolicyLength is the smallest value validateConfig will accept for
	// MinLength. 8 is the modern floor below which brute-force windows
	// collapse even on consumer GPUs; anything smaller is treated as a
	// weakened default and refused, not silently allowed.
	minPolicyLength = 8

	// maxPolicyLength is the largest value validateConfig will accept for
	// MaxLength. Argon2id hashes the entire input, so an unbounded maximum
	// is a CPU denial-of-service: a single oversized input can pin a
	// hashing thread for seconds. 1024 is generous for any reasonable
	// passphrase while still bounded.
	maxPolicyLength = 1024
)

// validateConfig returns an error if cfg contains invalid values.
// applyDefaults is always called before validateConfig, so Iterations and
// Parallelism are guaranteed to be ≥ 1 by the time this runs and the four
// *bool policy fields are guaranteed to be non-nil.
func validateConfig(cfg Config) error {
	if cfg.Memory < minMemory {
		return fmt.Errorf("memory must be at least %d KiB (8 MiB), got %d", minMemory, cfg.Memory)
	}
	if cfg.Memory > maxMemory {
		return fmt.Errorf("memory must be at most %d KiB (4 GiB), got %d", maxMemory, cfg.Memory)
	}
	if cfg.Iterations > maxIterations {
		return fmt.Errorf("iterations must be at most %d, got %d", maxIterations, cfg.Iterations)
	}
	if cfg.MinLength < minPolicyLength {
		return fmt.Errorf("min length must be at least %d, got %d", minPolicyLength, cfg.MinLength)
	}
	if cfg.MaxLength < cfg.MinLength {
		return fmt.Errorf("max length (%d) must be at least min length (%d)", cfg.MaxLength, cfg.MinLength)
	}
	if cfg.MaxLength > maxPolicyLength {
		return fmt.Errorf("max length must be at most %d, got %d", maxPolicyLength, cfg.MaxLength)
	}
	return nil
}
