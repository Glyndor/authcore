// Package field provides field-level encryption for a single database
// column, plus a blind index so the value stays searchable by exact
// equality without being readable.
//
// # What it is for
//
// Storing a user's email address encrypted, and still enforcing one
// account per address, is the case that drives this module. The
// caller writes the ciphertext into a TEXT column, the blind index
// into another column, and a UNIQUE index on the blind index gives
// the uniqueness guarantee without the database ever holding the
// plaintext. Right now every application writes the same sixty lines
// of AES-GCM plumbing by hand, which is the "right size? right RNG?
// right nonce?" problem this module closes.
//
// The module does NOT normalise its input. Lowercasing, trimming and
// Unicode folding are the caller's job, and auth/email and
// auth/username already do it. A module that normalised silently
// would make BlindIndex disagree with whatever the caller stored:
// index the same form you store, every time, or lookups miss.
//
//	fld, _ := field.New(auth, field.Config{Context: "email"})
//
//	// Write path: encrypt and produce the index the UNIQUE constraint
//	// runs against. Normalise first; the module never touches case.
//	plain := strings.ToLower(strings.TrimSpace(userInput))
//	ct, err := fld.Encrypt(plain)
//	if err != nil { return serverError() }
//	idx, err := fld.BlindIndex(plain)
//	if err != nil { return serverError() }
//	db.Exec(`INSERT INTO users (email_ct, email_idx) VALUES (?, ?)
//	         ON CONFLICT (email_idx) DO NOTHING`, ct, idx)
//
//	// Read path: hash the candidate the same way, look up the row,
//	// decrypt, then compare the index of what was decrypted with the
//	// index you looked up. A hit says only that the row's index column
//	// holds this value; a row whose index and ciphertext disagree (a
//	// write bug, or a write-capable attacker) passes the lookup and
//	// decrypts to something else.
//	candidate, err := fld.BlindIndex(plain)
//	if err != nil { return serverError() }
//	row := db.QueryRow(`SELECT email_ct FROM users WHERE email_idx = ?`,
//	                   candidate)
//	var ct string
//	if err := row.Scan(&ct); err != nil { return notFound() }
//	decrypted, err := fld.Decrypt(ct)
//	if err != nil { return serverError() }
//	check, err := fld.BlindIndex(decrypted)
//	if err != nil || check != candidate { return notFound() }
//
// # What is fixed and what is open
//
// The cryptographic layer is closed: AES-256-GCM, a 12-byte random
// nonce per Encrypt from crypto/rand, the HKDF-SHA256 derivation of
// the encryption and index keys from the library-managed refresh
// secret, the HMAC-SHA256 construction of the blind index, the
// length-prefixed binding of the configured Context into both the AES
// additional authenticated data and the blind index, and the
// base64-RawStdEncoding of nonce || sealed are all fixed. Weakening
// any of these lets a stolen ciphertext or a guessed value recover
// data the column is meant to protect.
//
// The policy layer is open with one required field: Context, the
// name of the database column the module is protecting for this
// instance. Context is not decoration; it is bound into the AAD
// and the index so a ciphertext from one column cannot be decrypted
// as another.
package field

import (
	"fmt"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/field/internal/blind"
	"github.com/Glyndor/authcore/auth/field/internal/kdf"
	"github.com/Glyndor/authcore/auth/field/internal/seal"
)

// Compile-time assertion: *Field must satisfy authcore.Module.
var _ authcore.Module = (*Field)(nil)

// refreshSecretLen is the byte length New demands from
// Keys().RefreshSecret(). HKDF-SHA256 reads the input secret as a
// single message; a short or absent secret would weaken every key
// derived from it, so New refuses anything other than 32 bytes.
const refreshSecretLen = 32

// Field is the field-level encryption module.
//
// Construct one instance per column at application startup using New,
// and share it across goroutines. Field is safe for concurrent use
// after construction.
//
// It carries configuration and the two derived keys (the AES key and
// the index HMAC key). It holds no per-call state, so two concurrent
// Encrypt or Decrypt calls are independent and a fresh nonce is drawn
// on every Encrypt.
//
// A zero-value Field is unusable: Encrypt, Decrypt and BlindIndex
// return ErrNotInitialised. New sets initialised as its last act, so
// a successful New is the only path to a working module.
type Field struct {
	cfg         Config
	log         authcore.Logger
	sealer      *seal.Sealer // AES-256-GCM bound to the derived encKey and the Context
	idxKey      []byte       // HMAC-SHA256 key for BlindIndex
	context     []byte       // bound Context as bytes, captured once for both AAD and the index
	initialised bool         // set by New; zero-value methods refuse to produce output
}

// New creates a Field module.
//
// cfg is required. The single field, Context, is the name of the
// database column the module is protecting; an empty Context is
// rejected with ErrInvalidConfig because it would make every field
// share one keyspace:
//
//	fld, err := field.New(auth, field.Config{Context: "email"})
//	fld, err := field.New(auth, field.Config{Context: "phone"})
//
// The module derives its encryption and index keys from
// Keys().RefreshSecret() using HKDF-SHA256. It generates no key
// material of its own.
//
// New returns a wrapped ErrInvalidConfig when the provider is
// unusable (a nil interface, a Logger() or Keys() that returns nil)
// or when Keys().RefreshSecret() is not exactly 32 bytes. A module
// that successfully returned is the only path to a working Field;
// every method on a zero value refuses to produce output.
func New(p authcore.Provider, cfg ...Config) (*Field, error) {
	if len(cfg) > 1 {
		return nil, fmt.Errorf("%w: at most one Config is allowed, got %d", ErrInvalidConfig, len(cfg))
	}
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	logger := p.Logger()
	if logger == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	keys := p.Keys()
	if keys == nil {
		return nil, fmt.Errorf("%w: provider.Keys() returned nil", ErrInvalidConfig)
	}

	var resolved Config
	if len(cfg) > 0 {
		resolved = applyDefaults(cfg[0])
	} else {
		resolved = DefaultConfig()
	}
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d",
			ErrInvalidConfig, l, refreshSecretLen)
	}

	encKey, err := kdf.Key(secret, kdf.EncryptionInfo)
	if err != nil {
		return nil, fmt.Errorf("field: derive encryption key: %w", err)
	}
	idxKey, err := kdf.Key(secret, kdf.IndexInfo)
	if err != nil {
		return nil, fmt.Errorf("field: derive index key: %w", err)
	}

	sealer, err := seal.New(encKey, []byte(resolved.Context))
	if err != nil {
		return nil, err
	}

	f := &Field{
		cfg:         resolved,
		log:         logger,
		sealer:      sealer,
		idxKey:      idxKey,
		context:     []byte(resolved.Context),
		initialised: true,
	}
	f.log.Info("field: module initialised (context=%q)", resolved.Context)
	return f, nil
}

// Name returns the module's unique identifier. It implements
// authcore.Module.
func (f *Field) Name() string { return "field" }

// Encrypt seals plaintext under the bound Context and returns a
// base64-encoded ciphertext. The output drops into a TEXT column as
// is; a BYTEA-style column can store the raw bytes by passing the
// string through base64.RawStdEncoding.DecodeString.
//
// A fresh 12-byte nonce is drawn from crypto/rand on every call, so
// encrypting the same plaintext twice produces different ciphertexts
// and the module never derives the nonce from the plaintext (a
// repeated nonce under the same key destroys GCM).
//
// The bound Context is fed to GCM as additional authenticated data,
// length-prefixed with a big-endian uint32 so the AAD is unambiguous
// no matter what bytes the Context contains. A ciphertext written
// for "email" cannot be decrypted as "phone" because the AAD will
// differ and GCM authentication will fail.
//
// Encrypt returns ErrNotInitialised on a zero-value Field, so a module
// that was never constructed by New cannot emit ciphertext derived
// from an empty AES key.
func (f *Field) Encrypt(plaintext string) (string, error) {
	if !f.initialised {
		return "", ErrNotInitialised
	}
	return f.sealer.Seal(plaintext)
}

// Decrypt reverses Encrypt for a ciphertext that was produced under
// the same Context. It returns ErrDecrypt for every failure mode: an
// input shorter than the nonce, an input that is not valid base64,
// and a failed GCM authentication tag. The three are not
// distinguished, because which one failed is information about the
// stored data and the caller has nothing useful to do differently.
//
// Decrypt never panics, including on input shorter than the nonce:
// the base64 decoder would otherwise panic on a too-short slice, and
// a zero-value Field would panic on the missing AEAD before any of
// the input checks could run.
//
// Decrypt returns ErrNotInitialised on a zero-value Field, so a
// module that was never constructed by New cannot claim to read
// data it has no key to read.
func (f *Field) Decrypt(ciphertext string) (string, error) {
	if !f.initialised {
		return "", ErrNotInitialised
	}
	plain, err := f.sealer.Open(ciphertext)
	if err != nil {
		return "", ErrDecrypt
	}
	return plain, nil
}

// BlindIndex returns a deterministic, fixed-size hex string for value
// under the bound Context. The caller passes the result to the
// database the same way it would pass a SHA-256 hash, and a UNIQUE
// index on the column enforces one row per value.
//
// The caller MUST normalise value first (lowercase, trim, fold, etc.)
// and BlindIndex the same form it stores; a module that normalised
// silently would make BlindIndex disagree with whatever the caller
// stored, and lookups would miss.
//
// The output is hex(HMAC-SHA256(idxKey, len(context)||context ||
// len(value)||value)), each length a big-endian uint32. The length
// prefix is what makes the encoding unambiguous: ("a", "bc") and
// ("ab", "c") cannot collide, and neither can ("email", "user@x")
// and ("emailuser", "@x"). A separator byte would only disambiguate
// while no field contained it, and a Go string can contain any byte.
//
// BlindIndex returns ErrNotInitialised on a zero-value Field, so a
// module that was never constructed by New cannot emit an index
// derived from an empty key under an empty context.
func (f *Field) BlindIndex(value string) (string, error) {
	if !f.initialised {
		return "", ErrNotInitialised
	}
	return blind.Index(f.idxKey, f.context, value), nil
}
