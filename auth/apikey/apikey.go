// Package apikey issues and verifies opaque API keys for authcore.
//
// # What it is for
//
// API keys authenticate machines — a CLI, a service, a webhook caller — where
// a username/password or a short-lived JWT does not fit. authcore generates a
// high-entropy opaque key, returns a hash for you to store, and verifies a
// presented key against that hash in constant time. The library never stores
// anything; you own the database.
//
// # Key shape
//
//		<prefix>_<id>_<secret>
//
//	  - prefix — a short fixed tag (default "ak") so a leaked key is recognisable
//	    in logs and can be scanned for.
//	  - id     — a random public identifier. Store it in plaintext and use it as
//	    the database lookup key, so verification is an O(1) row fetch, not a scan.
//	  - secret — 256 bits of CSPRNG output, hex-encoded. Only its keyed hash is
//	    stored.
//
// # Storage model
//
// The key is high-entropy random, so it is hashed with keyed HMAC-SHA256 (fast,
// constant-time-verifiable, peppered with the library's managed secret) rather
// than a slow password hash — a per-request API call must not pay Argon2id cost,
// and a 256-bit random key has no need of it.
//
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	keyMod, _ := apikey.New(auth)
//
//	// Issue — show key.Key to the user ONCE; store key.ID and key.Hash.
//	key, _ := keyMod.Generate()
//	db.StoreAPIKey(key.ID, key.Hash, userID)
//
//	// Verify — extract the id, fetch the row, compare in constant time.
//	id, err := keyMod.ParseID(presented)
//	if err != nil { return http.StatusUnauthorized }
//	row, err := db.FindAPIKey(id)
//	if err != nil || !keyMod.Verify(presented, row.Hash) { return http.StatusUnauthorized }
package apikey

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey/internal/digest"
	"github.com/Glyndor/authcore/auth/apikey/internal/format"
)

const (
	// refreshSecretLen is the byte length New demands from
	// Keys().RefreshSecret(). The HMAC-SHA256 pepper must match across
	// all servers that share an installation; a short or absent secret
	// would silently weaken every key derived from it.
	refreshSecretLen = 32
)

// Compile-time assertion: *APIKey must satisfy authcore.Module.
var _ authcore.Module = (*APIKey)(nil)

// APIKey is the opaque API-key module.
//
// Construct one instance at application startup using New and share it across
// goroutines. APIKey is safe for concurrent use after construction.
//
// A zero-value APIKey is unusable: Generate and Hash return ErrNotInitialised,
// and Verify returns false. New sets initialised as its last act, so a
// successful New is the only path to a working module.
type APIKey struct {
	cfg         Config
	log         authcore.Logger
	secret      []byte // HMAC-SHA256 pepper, sourced from the parent AuthCore instance
	initialised bool   // set by New; zero-value methods refuse to produce output
}

// GeneratedKey is the result of Generate.
//
// Show Key to the user exactly once — it is never recoverable afterwards.
// Persist ID (plaintext, the lookup key) and Hash (never the raw key).
type GeneratedKey struct {
	// Key is the full opaque API key to hand to the caller, once.
	Key string
	// ID is the public identifier embedded in Key. Store it and use it to look
	// up the stored hash on verification.
	ID string
	// Hash is the keyed HMAC-SHA256 digest of Key. Store only this.
	Hash string
}

// New creates an APIKey module.
//
// cfg is optional — omit it for the default key prefix ("ak"):
//
//	keyMod, err := apikey.New(auth)
//	keyMod, err := apikey.New(auth, apikey.Config{Prefix: "svc"})
//
// New returns a wrapped ErrInvalidConfig when the provider is unusable
// (a nil interface, a Logger() or Keys() that returns nil) or when
// Keys().RefreshSecret() is not exactly 32 bytes. A module that
// successfully returned is the only path to a working APIKey; every
// method on a zero value refuses to produce output.
func New(p authcore.Provider, cfg ...Config) (*APIKey, error) {
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
		resolved = cfg[0]
	}
	resolved = applyDefaults(resolved)
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d",
			ErrInvalidConfig, l, refreshSecretLen)
	}

	a := &APIKey{
		cfg:         resolved,
		log:         logger,
		secret:      bytes.Clone(secret),
		initialised: true,
	}
	a.log.Info("apikey: module initialised (prefix=%s)", resolved.Prefix)
	return a, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (a *APIKey) Name() string { return "apikey" }

// Generate mints a new opaque API key. The id and secret are independent
// CSPRNG draws; the returned Hash is what you store.
//
// Generate returns ErrNotInitialised on a zero-value APIKey, so a module
// that was never constructed by New cannot emit output derived from an
// empty HMAC pepper.
func (a *APIKey) Generate() (*GeneratedKey, error) {
	if a == nil || !a.initialised {
		return nil, ErrNotInitialised
	}
	idBytes := make([]byte, format.IDLen)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("apikey: generate id: %w", err)
	}
	secretBytes := make([]byte, format.SecretLen)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("apikey: generate secret: %w", err)
	}

	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	full := format.Join(a.cfg.Prefix, id, secret)

	return &GeneratedKey{Key: full, ID: id, Hash: digest.Hash(a.secret, full)}, nil
}

// Hash returns the keyed HMAC-SHA256 digest of key. Use it to recompute the
// stored value (it matches GeneratedKey.Hash for the same key).
//
// Hash returns ErrNotInitialised on a zero-value APIKey, so a module that
// was never constructed by New cannot emit a digest derived from an empty
// HMAC pepper.
func (a *APIKey) Hash(key string) (string, error) {
	if a == nil || !a.initialised {
		return "", ErrNotInitialised
	}
	return digest.Hash(a.secret, key), nil
}

// Verify reports whether key matches storedHash, comparing in constant time to
// prevent timing attacks.
//
// Verify returns false on a zero-value APIKey: a module with no HMAC pepper
// cannot verify anything, and answering true would let a caller mistake
// "no key was used" for "the key matched".
func (a *APIKey) Verify(key, storedHash string) bool {
	if a == nil || !a.initialised {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(digest.Hash(a.secret, key)), []byte(storedHash)) == 1
}

// ParseID extracts the public identifier from a presented key without verifying
// it, so you can fetch the stored hash before the constant-time comparison.
//
// The full key shape is <prefix>_<id>_<secret>. ParseID accepts exactly that
// three-field shape: an id of 32 lowercase hex characters and a secret of 64
// lowercase hex characters, with nothing before, between or after them except
// the two field separators. Any extra field, an id or secret of the wrong
// length, or a non-lowercase-hex character is rejected with ErrInvalidKey, so
// the caller can rely on the returned id as the lookup key for a row that
// was produced by Generate.
//
// It returns ErrInvalidKey if key is not a well-formed key for this module
// (wrong prefix, wrong structure, malformed id, malformed secret, or any
// extra trailing field), and ErrNotInitialised on a zero-value APIKey.
func (a *APIKey) ParseID(key string) (string, error) {
	// A zero-value APIKey has an empty prefix, and without this it accepted
	// "_<id>_<secret>" and returned an id for it.
	if a == nil || !a.initialised {
		return "", ErrNotInitialised
	}
	id, ok := format.ParseID(a.cfg.Prefix, key)
	if !ok {
		return "", ErrInvalidKey
	}
	return id, nil
}
