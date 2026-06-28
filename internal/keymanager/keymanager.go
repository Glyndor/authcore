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
//
// On subsequent calls the existing files are loaded and validated; no new
// material is generated unless a file is missing.
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

	if err := ensureGitignore(dir); err != nil {
		return nil, fmt.Errorf("write .gitignore in %q: %w", dir, err)
	}

	priv, pub, err := loadOrGenerateEd25519(dir, log)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key pair: %w", err)
	}

	secret, err := loadOrGenerateRefreshSecret(dir, log)
	if err != nil {
		return nil, fmt.Errorf("refresh secret: %w", err)
	}

	return &KeyManager{
		dir:           dir,
		privateKey:    priv,
		publicKey:     pub,
		refreshSecret: secret,
		keyID:         computeKeyID(pub),
	}, nil
}

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

// RefreshSecret returns the 32-byte secret used as the HMAC-SHA256 key
// when hashing refresh tokens before database storage.
// The returned slice must not be modified by the caller.
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

// ensureGitignore writes a catch-all .gitignore inside dir if one does
// not already exist. It is idempotent.
func ensureGitignore(dir string) error {
	path := filepath.Join(dir, fileGitignore)
	if _, err := os.Stat(path); err == nil {
		return nil // already present
	}
	return os.WriteFile(path, []byte(gitignoreContent), 0600)
}
