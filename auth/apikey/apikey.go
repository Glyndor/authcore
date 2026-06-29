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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Glyndor/authcore"
)

const (
	idLen     = 16 // bytes — 128-bit public identifier, hex-encoded (32 chars)
	secretLen = 32 // bytes — 256-bit secret, hex-encoded (64 chars)
)

// Compile-time assertion: *APIKey must satisfy authcore.Module.
var _ authcore.Module = (*APIKey)(nil)

// APIKey is the opaque API-key module.
//
// Construct one instance at application startup using New and share it across
// goroutines. APIKey is safe for concurrent use after construction.
type APIKey struct {
	cfg    Config
	log    authcore.Logger
	secret []byte // HMAC-SHA256 pepper, sourced from the parent AuthCore instance
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
func New(p authcore.Provider, cfg ...Config) (*APIKey, error) {
	var resolved Config
	if len(cfg) > 0 {
		resolved = cfg[0]
	}
	resolved = applyDefaults(resolved)
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	a := &APIKey{cfg: resolved, log: p.Logger(), secret: p.Keys().RefreshSecret()}
	a.log.Info("apikey: module initialised (prefix=%s)", resolved.Prefix)
	return a, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (a *APIKey) Name() string { return "apikey" }

// Generate mints a new opaque API key. The id and secret are independent
// CSPRNG draws; the returned Hash is what you store.
func (a *APIKey) Generate() (*GeneratedKey, error) {
	idBytes := make([]byte, idLen)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("apikey: generate id: %w", err)
	}
	secretBytes := make([]byte, secretLen)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("apikey: generate secret: %w", err)
	}

	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	full := a.cfg.Prefix + "_" + id + "_" + secret

	return &GeneratedKey{Key: full, ID: id, Hash: a.hash(full)}, nil
}

// Hash returns the keyed HMAC-SHA256 digest of key. Use it to recompute the
// stored value (it matches GeneratedKey.Hash for the same key).
func (a *APIKey) Hash(key string) string {
	return a.hash(key)
}

// Verify reports whether key matches storedHash, comparing in constant time to
// prevent timing attacks.
func (a *APIKey) Verify(key, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(a.hash(key)), []byte(storedHash)) == 1
}

// ParseID extracts the public identifier from a presented key without verifying
// it, so you can fetch the stored hash before the constant-time comparison.
//
// It returns ErrInvalidKey if key is not a well-formed key for this module
// (wrong prefix, wrong structure, or a malformed id).
func (a *APIKey) ParseID(key string) (string, error) {
	prefix := a.cfg.Prefix + "_"
	rest, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return "", ErrInvalidKey
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok || secret == "" {
		return "", ErrInvalidKey
	}
	if len(id) != hex.EncodedLen(idLen) || !isHex(id) {
		return "", ErrInvalidKey
	}
	return id, nil
}

// hash computes the keyed HMAC-SHA256 hex digest of key.
func (a *APIKey) hash(key string) string {
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// isHex reports whether s is all lowercase hexadecimal digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
