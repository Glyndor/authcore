// Package field holds the configuration for the field-level encryption
// module. See field.go for the cryptography and the data flow; this file
// is the config surface only.
package field

import "fmt"

// Config holds the field module configuration.
//
// The configuration is split into two layers, matching the authcore
// principle documented in docs/guides/configuration.md:
//
//   - The cryptographic layer is CLOSED and is not configurable here.
//     AES-256-GCM, the 12-byte random nonce per Encrypt, the HKDF-SHA256
//     derivation of the encryption and index keys from the library-managed
//     refresh secret, the HMAC-SHA256 construction of the blind index, the
//     length-prefixed binding of the context into both the AAD and the
//     index, and the base64 encoding of the ciphertext are all fixed.
//     Weakening any of these lets a stolen ciphertext or a guessed value
//     recover data the column is meant to protect.
//   - The policy layer is OPEN with one required field: Context, the name
//     of the database column the module is protecting for this instance.
//
// What stays fixed regardless of configuration:
//
//   - Encryption: AES-256-GCM with a 12-byte random nonce per call
//   - Nonce source: crypto/rand (never derived from the plaintext, never
//     counted; a repeated nonce under the same key destroys GCM)
//   - Additional authenticated data: the bound Context, length-prefixed
//     with a big-endian uint32
//   - Key derivation: HKDF-SHA256 from Keys().RefreshSecret(), with
//     distinct info labels for the encryption key and the index key so
//     the two constructions cannot share a weakness
//   - Blind index: HMAC-SHA256(idxKey, len(context)||context ||
//     len(value)||value), each length a big-endian uint32, hex-encoded
//   - Ciphertext encoding: base64.RawStdEncoding of nonce || sealed
//
// Start from Config and set Context before passing the value to New,
// since Context has no zero-value default and validateConfig refuses
// an empty one:
//
//	fld, err := field.New(auth, field.Config{Context: "email"})
type Config struct {
	// Context names the field this instance protects. It is bound into
	// the AES additional authenticated data and into the blind index
	// input, so a ciphertext lifted from one column cannot be decrypted
	// as another column, and a blind index computed for one field never
	// matches another.
	//
	// Context has no default: a caller who does not name the field is
	// telling the module nothing, and silently accepting "" would make
	// every field share one keyspace. validateConfig refuses the empty
	// string at New.
	Context string
}

// DefaultConfig returns a zero-value Config. The caller MUST set
// Context before passing the result to New; validateConfig refuses the
// empty string that flows from a forgotten assignment.
//
//	fld, err := field.New(auth, field.DefaultConfig())
//	fld, err := field.New(auth, field.Config{Context: "email"})
//
// Unlike auth/credential.DefaultConfig, which fills a safe policy value
// the caller can ignore, this module has no safe "unnamed field"
// value, so the default is the zero Config and validateConfig is the
// gate. The trio (DefaultConfig / applyDefaults / validateConfig) is
// kept in shape so the constructor wiring matches the rest of authcore.
func DefaultConfig() Config {
	return Config{}
}

// applyDefaults is a pass-through for the field module.
//
// Context is a plain string where "" is not meaningful: an empty
// Context would make every field share one keyspace, which is the
// exact failure this module exists to prevent. Filling "" with a
// default here would silently turn a caller bug into a single shared
// keyspace, so validateConfig is the only thing that decides what
// Context values are allowed. applyDefaults exists only so the
// function trio (DefaultConfig / applyDefaults / validateConfig)
// matches the shape used across the rest of authcore.
func applyDefaults(cfg Config) Config {
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
func validateConfig(cfg Config) error {
	if cfg.Context == "" {
		return fmt.Errorf("context must not be empty")
	}
	return nil
}
