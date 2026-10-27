// Package phc encodes and strictly parses the PHC string an Argon2id hash is
// stored as: $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<key>.
package phc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// The sizes Hash produces and Parse requires, and the ceilings that keep a
// stored hash from dictating an unbounded allocation.
const (
	SaltLen       = 16              // bytes: 128 bits of entropy per hash
	KeyLen        = 32              // bytes: 256-bit Argon2id output
	MinMemory     = 8 * 1024        // 8 MiB in KiB
	MaxMemory     = 4 * 1024 * 1024 // 4 GiB in KiB: prevents accidental DoS
	MaxIterations = 20              // beyond this, hashing takes tens of seconds
)

// maxEncodedLen includes the fixed syntax, uint32/uint8 decimal widths and
// the unpadded base64 lengths of the fixed salt and key. Every canonical PHC
// accepted by Parse fits, independently of the configured work factor.
const maxEncodedLen = len("$argon2id$v=19$m=,t=,p=$$") + 10 + 10 + 3 + (SaltLen*8+5)/6 + (KeyLen*8+5)/6

// ErrInvalid is wrapped by every error Parse returns. The password package
// wraps it again under its own ErrInvalidHash, so its text is that sentinel's.
var ErrInvalid = errors.New("password: invalid hash format")

// Params are the Argon2id cost parameters a PHC string carries.
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// Encode writes the PHC string for an Argon2id hash: the version, the
// memory, iteration and parallelism parameters of cfg, and salt and key in
// unpadded standard base64. It is the only form Parse accepts.
func Encode(cfg Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		cfg.Memory,
		cfg.Iterations,
		cfg.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// splitSegments refuses a string longer than any canonical hash before it is
// split or decoded, then cuts it into its six dollar-separated segments.
func splitSegments(phcHash string) ([]string, error) {
	if len(phcHash) > maxEncodedLen {
		return nil, fmt.Errorf("%w: encoded hash exceeds the format size limit", ErrInvalid)
	}
	// Expected: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
	// strings.Split on "$" produces: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<key>"]
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return nil, fmt.Errorf("%w: expected 6 dollar-separated segments, got %d", ErrInvalid, len(parts))
	}
	return parts, nil
}

// Parse decodes a PHC string produced by Hash and returns the embedded
// Argon2id parameters, the decoded salt, and the decoded derived key.
//
// Every returned error wraps ErrInvalid so the caller can match a single
// sentinel regardless of which check refused the string. Diagnostics describe
// the failed check without including input values.
func Parse(phcHash string) (Params, []byte, []byte, error) {
	parts, err := splitSegments(phcHash)
	if err != nil {
		return Params{}, nil, nil, err
	}
	// The PHC format starts with a dollar, so the first segment is empty. Any
	// text before it passes the count check above while leaving the rest of the
	// parser a string it cannot tell apart from a real hash, and "junk" + hash
	// then verifies the same password the clean hash does.
	if parts[0] != "" {
		return Params{}, nil, nil, fmt.Errorf("%w: unexpected text before the first dollar", ErrInvalid)
	}
	if parts[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported algorithm, want argon2id", ErrInvalid)
	}

	version, err := parseLabeledUint32(parts[2], "v")
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parse version: %w", ErrInvalid, err)
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported Argon2 version, want %d", ErrInvalid, argon2.Version)
	}

	// The parameter segment is three "label=N" fields separated by commas.
	// Splitting on "," first lets the labeled parsers reject trailing text inside
	// a single field ("m=65536junk"), which fmt.Sscanf's %d accepts silently.
	paramFields := strings.Split(parts[3], ",")
	if len(paramFields) != 3 {
		return Params{}, nil, nil, fmt.Errorf("%w: expected 3 comma-separated parameter fields, got %d", ErrInvalid, len(paramFields))
	}
	mem, err := parseLabeledUint32(paramFields[0], "m")
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parse memory: %w", ErrInvalid, err)
	}
	iter, err := parseLabeledUint32(paramFields[1], "t")
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parse iterations: %w", ErrInvalid, err)
	}
	par, err := parseLabeledUint8(paramFields[2], "p")
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parse parallelism: %w", ErrInvalid, err)
	}

	cfg := Params{Memory: mem, Iterations: iter, Parallelism: par}

	// Bound the parsed parameters before handing them to argon2.IDKey. A
	// corrupted or attacker-supplied hash with m=4_000_000_000 would otherwise
	// cause the verifier to attempt a multi-TiB allocation and crash the
	// process. Reuse the same ceilings validateConfig enforces at construction.
	if cfg.Memory < MinMemory || cfg.Memory > MaxMemory {
		return Params{}, nil, nil, fmt.Errorf("%w: memory parameter out of range: want [%d, %d]", ErrInvalid, MinMemory, MaxMemory)
	}
	if cfg.Iterations < 1 || cfg.Iterations > MaxIterations {
		return Params{}, nil, nil, fmt.Errorf("%w: iterations parameter out of range: want [1, %d]", ErrInvalid, MaxIterations)
	}
	if cfg.Parallelism < 1 {
		return Params{}, nil, nil, fmt.Errorf("%w: parallelism parameter out of range: want >= 1", ErrInvalid)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: decode salt: %w", ErrInvalid, err)
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: decode key: %w", ErrInvalid, err)
	}

	// Reject hashes whose salt or key are not the fixed sizes Hash produces.
	// A truncated hash with an empty key segment would otherwise reach
	// argon2.IDKey with KeyLen=0, which panics (nil dereference) and crashes
	// the process. Enforcing the exact lengths fails closed on any corrupted
	// or attacker-supplied PHC string before it can reach the KDF.
	if len(salt) != SaltLen {
		return Params{}, nil, nil, fmt.Errorf("%w: salt has wrong length: got %d bytes, want %d", ErrInvalid, len(salt), SaltLen)
	}
	if len(key) != KeyLen {
		return Params{}, nil, nil, fmt.Errorf("%w: derived key has wrong length: got %d bytes, want %d", ErrInvalid, len(key), KeyLen)
	}

	// Accept only the exact string Hash writes for these values. The checks
	// above read each field leniently in ways no encoder produces: strconv
	// takes "m=08192", and the base64 decoder skips "\n" and "\r" and ignores
	// the unused bits of the last character. Each of those let a second
	// spelling of one hash verify; a fuzzer comparing against the re-encoded
	// form found the last two within a second (#456).
	if phcHash != Encode(cfg, salt, key) {
		return Params{}, nil, nil, fmt.Errorf("%w: hash is not in canonical form", ErrInvalid)
	}

	return cfg, salt, key, nil
}

// labeledValue returns the N of a field of the form "label=N", unparsed. It
// refuses a missing label and an empty value; the typed parsers below refuse
// everything else.
func labeledValue(field, label string) (string, error) {
	prefix := label + "="
	if !strings.HasPrefix(field, prefix) {
		return "", fmt.Errorf("missing %s= prefix", label)
	}
	rest := field[len(prefix):]
	if rest == "" {
		return "", fmt.Errorf("empty %s value", label)
	}
	return rest, nil
}

// parseLabeledUint32 reads a field of the form "label=N" and returns N, which
// must be a decimal that fits in 32 bits. The whole field must be consumed:
// "v=19junk" is rejected because strconv rejects it, and "v=19,extra=1" never
// reaches here because the caller splits on the separator first.
//
// Parse at the target width, never wider and then narrow. Measured before this
// existed: fmt.Sscanf("v=19junk", ...) silently bound v to 19, and the
// replacement that parsed at 64 bits and converted afterwards let
// m=4294975488 verify as m=8192 (#451).
func parseLabeledUint32(field, label string) (uint32, error) {
	rest, err := labeledValue(field, label)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", label, err.(*strconv.NumError).Err)
	}
	return uint32(n), nil
}

// parseLabeledUint8 is parseLabeledUint32 for a value that must fit in 8 bits.
// Before #451, p=257 verified as p=1.
func parseLabeledUint8(field, label string) (uint8, error) {
	rest, err := labeledValue(field, label)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(rest, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", label, err.(*strconv.NumError).Err)
	}
	return uint8(n), nil
}
