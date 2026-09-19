// Package keymanager handles the creation, storage, and loading of
// authcore's cryptographic key material.
//
// On first use it creates a ".authcore" directory (or a caller-specified
// path), writes a .gitignore that prevents secrets from being committed,
// and generates the following files:
//
//	ed25519_private.pem  — Ed25519 private key, PKCS#8 PEM, mode 0600
//	ed25519_public.pem   — Ed25519 public key,  PKIX  PEM, mode 0644
//	refresh_secret.key   — 32-byte HMAC-SHA256 secret, hex-encoded, mode 0600
//	metadata.json        — on-disk layout version, mode 0600
//
// On subsequent calls the existing files are loaded and validated; no new
// material is generated unless a file is missing.
//
// metadata.json records which layout wrote the directory, so a future release
// that changes the on-disk format can migrate what is there instead of
// regenerating it — regenerating would invalidate every refresh-token and
// API-key hash the consumer has stored, logging out all of their users. A
// directory written before this file existed carries no marker; it is adopted
// in place, keys untouched. A directory reporting a newer format is refused
// rather than parsed on a guess.
//
// Key-file loading is size-capped at 4 KiB. A healthy Ed25519 PEM is ~200
// bytes and a hex-encoded HMAC secret is 65 bytes, so the cap leaves
// comfortable headroom for PEM comment headers while refusing a corrupted
// or attacker-replaced key file that would otherwise be loaded whole into
// memory before PEM decoding rejects it.
//
// The KeyManager is read-only after construction and safe for concurrent use.
package keymanager

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// File names written inside the key directory.
const (
	filePrivateKey    = "ed25519_private.pem"
	filePublicKey     = "ed25519_public.pem"
	fileRefreshSecret = "refresh_secret.key"
	fileGitignore     = ".gitignore"

	// gitignoreContent prevents every file in the directory from being tracked.
	gitignoreContent = "# Managed by authcore — do not commit these files.\n*\n"

	// dirMode restricts the key directory to the owner only.
	dirMode = 0700
)

// logger is the minimal logging dependency for the key manager.
// It is intentionally unexported and narrow.
// Any authcore.Logger value satisfies it via Go's structural typing.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// KeyManager holds cryptographic material loaded at startup.
// All fields are immutable after New returns; no mutex is required.
type KeyManager struct {
	dir           string
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	refreshSecret []byte
	keyID         string
}

// New initialises the KeyManager for the given directory.
//
// It creates the directory if it does not exist, writes a protective
// .gitignore, then generates or loads each key file.
//
// dir must be a writable path. Use "." to place the ".authcore" folder
// in the current working directory, or provide an absolute path for
// containerised / restricted environments.
func New(dir string, log logger) (*KeyManager, error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create key directory %q: %w", dir, err)
	}

	// MkdirAll does not tighten a directory that already exists, so a pre-created
	// or volume-mounted KeysDir could sit at a looser mode (e.g. 0755). Tighten
	// it to owner-only — but only ever tighten. An operator who hands over a
	// stricter directory (0500 for a read-only mounted secret) means it, and
	// widening the permissions on the directory that holds the private key would
	// be the opposite of what this exists for. A failure here is not fatal — the
	// private key and refresh secret are still written 0600 — so warn rather than
	// abort.
	if err := tightenDirMode(dir); err != nil {
		log.Warn("authcore/keymanager: could not tighten key directory %q to %o: %v", dir, dirMode, err)
	}

	// The .gitignore is a convenience guard against committing keys; it is not
	// security-critical. On a read-only KeysDir (a mounted secret) the write
	// fails harmlessly — warn and carry on rather than refusing to start.
	if err := ensureGitignore(dir); err != nil {
		log.Warn("authcore/keymanager: could not write .gitignore in %q (continuing): %v", dir, err)
	}

	// Read the layout marker before anything is parsed or generated: a directory
	// written by a newer authcore must be refused while its files are still
	// untouched, not after a loader from this build has interpreted them.
	meta, err := readMetadata(dir)
	if err != nil {
		return nil, err
	}

	// Fail closed on a partially-populated directory before generating anything,
	// so a missing refresh secret beside an existing key pair is reported rather
	// than silently regenerated (which would invalidate stored refresh hashes).
	if err := checkKeyDirConsistency(dir); err != nil {
		return nil, err
	}

	priv, pub, err := loadOrGenerateEd25519(dir, log)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key pair: %w", err)
	}

	secret, err := loadOrGenerateRefreshSecret(dir, log)
	if err != nil {
		return nil, fmt.Errorf("refresh secret: %w", err)
	}

	keyID := computeKeyID(pub)

	// Record the layout last, once the keys it describes are known good. A
	// directory from before this file existed is adopted in place here — the
	// key material is never rewritten, only described.
	syncMetadata(dir, meta, keyID, log)

	return &KeyManager{
		dir:           dir,
		privateKey:    priv,
		publicKey:     pub,
		refreshSecret: secret,
		keyID:         keyID,
	}, nil
}

// KeyID derives the stable key identifier for pub — the same value a
// KeyManager reports for its own key. It is exported so the JWT module can
// index additional verification keys (during rotation) by the same id without
// duplicating the derivation.
func KeyID(pub ed25519.PublicKey) string { return computeKeyID(pub) }

// computeKeyID derives a stable identifier from a public key.
// It returns the first 8 bytes of the SHA-256 digest of the raw public key
// bytes, hex-encoded (16 lowercase characters). The value changes automatically
// when the key is rotated, making it suitable as a JOSE "kid" header value.
func computeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// PrivateKey returns the Ed25519 private key used for signing operations.
// The returned slice must not be modified by the caller.
func (km *KeyManager) PrivateKey() ed25519.PrivateKey {
	return km.privateKey
}

// PublicKey returns the Ed25519 public key used for signature verification.
// The returned slice must not be modified by the caller.
func (km *KeyManager) PublicKey() ed25519.PublicKey {
	return km.publicKey
}

// RefreshSecret returns the 32-byte secret used as the HMAC-SHA256 key when
// hashing refresh tokens (and, in the apikey module, as the key-hash pepper).
// The returned slice must not be modified by the caller.
//
// The secret is intentionally shared across those uses. HMAC-SHA256 is a secure
// PRF under multi-purpose use and the message namespaces differ (a compact JWT
// vs an "ak_<id>_<secret>" key), so there is no cross-protocol forgery. It is
// not split into per-use subkeys (e.g. via HKDF) because the resulting hashes
// are stored by the consumer: changing the derivation would invalidate every
// stored refresh-token and API-key hash on upgrade, forcing all users to
// re-authenticate — a breaking change the library avoids by design.
func (km *KeyManager) RefreshSecret() []byte {
	return km.refreshSecret
}

// KeyID returns the stable identifier for the current signing key.
// See computeKeyID for the derivation details.
func (km *KeyManager) KeyID() string {
	return km.keyID
}

// Dir returns the absolute path of the key directory.
func (km *KeyManager) Dir() string {
	return km.dir
}

// tightenDirMode removes any permission bit outside dirMode from dir, and
// leaves a directory that is already at or below dirMode untouched.
//
// Chmodding unconditionally would also *raise* a stricter mode to 0700, which
// is why the current mode is read first: 0755 becomes 0700, while 0500 stays
// 0500. On a platform without Unix permission bits the mode carries no group
// or world bits to strip, so this is a no-op there.
func tightenDirMode(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	if mode&^dirMode == 0 {
		return nil // already at least this strict
	}
	return os.Chmod(dir, mode&dirMode)
}

// ensureGitignore writes a catch-all .gitignore inside dir if one does
// not already exist. It is idempotent.
func ensureGitignore(dir string) error {
	path := filepath.Join(dir, fileGitignore)
	if exists(dir, fileGitignore) {
		return nil // already present
	}
	return createExclusive(path, []byte(gitignoreContent), 0600)
}
