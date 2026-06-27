package keymanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// refreshSecretLen is the number of raw bytes in a refresh secret.
// 32 bytes gives 256 bits of entropy, matching the HMAC-SHA256 key size.
const refreshSecretLen = 32

// maxKeyFileSize caps the bytes the key loader will read from disk. A healthy
// Ed25519 PEM file is ~200 bytes and a hex-encoded HMAC secret is 65 bytes,
// so 4 KiB leaves comfortable headroom for PEM comment headers without ever
// reading an oversized file. The cap protects startup from a corrupted or
// attacker-replaced key file that would otherwise be loaded whole into memory.
const maxKeyFileSize = 4 * 1024

// readCapped reads up to maxKeyFileSize bytes from path and returns an error
// if the file is larger. It replaces os.ReadFile at every key-loading site.
func readCapped(path string) ([]byte, error) {
	// #nosec G304 -- path derived from trusted config.KeysDir and fixed filename, not user input
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Stat first so an obviously oversized file is rejected before any read.
	if fi, err := f.Stat(); err == nil && fi.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("file %q is %d bytes, exceeds %d-byte cap", path, fi.Size(), maxKeyFileSize)
	}

	// Read at most maxKeyFileSize+1 bytes. If the +1 byte actually arrives,
	// the file streams more than the stat reported (symlink race, pipe-like
	// path) and the loader refuses it.
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("file %q exceeds %d-byte cap", path, maxKeyFileSize)
	}
	return data, nil
}

// ----- Ed25519 key pair -------------------------------------------------------

// loadOrGenerateEd25519 returns an Ed25519 key pair, generating and
// persisting them if the PEM files do not exist.
func loadOrGenerateEd25519(dir string, log logger) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privPath := filepath.Join(dir, filePrivateKey)
	pubPath := filepath.Join(dir, filePublicKey)

	_, privErr := os.Stat(privPath)
	_, pubErr := os.Stat(pubPath)

	switch {
	case privErr == nil && pubErr == nil:
		// Both files exist — load and validate them.
		log.Info("authcore/keymanager: loading existing Ed25519 key pair from %s", dir)
		return loadEd25519(privPath, pubPath)

	case privErr != nil && pubErr != nil:
		// Neither exists — generate a fresh pair.
		log.Warn("authcore/keymanager: Ed25519 key pair not found, generating new keys in %s", dir)
		return generateAndSaveEd25519(privPath, pubPath)

	default:
		// Only one file is present — this is an inconsistent state.
		return nil, nil, fmt.Errorf(
			"key directory %q is in an inconsistent state: "+
				"one of {%s, %s} is missing; "+
				"delete both files to trigger regeneration",
			dir, filePrivateKey, filePublicKey,
		)
	}
}

// generateAndSaveEd25519 creates a fresh Ed25519 key pair and writes it to disk.
func generateAndSaveEd25519(privPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key pair: %w", err)
	}
	if err := writePrivateKey(privPath, priv); err != nil {
		return nil, nil, err
	}
	if err := writePublicKey(pubPath, pub); err != nil {
		// Best-effort cleanup: remove the private key if the public write fails
		// so the directory does not end up in an inconsistent state.
		_ = os.Remove(privPath)
		return nil, nil, err
	}
	return priv, pub, nil
}

// loadEd25519 reads and validates an Ed25519 key pair from disk.
func loadEd25519(privPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	priv, err := readPrivateKey(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load public key: %w", err)
	}
	// Sanity check: the public key must match the private key.
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, nil, fmt.Errorf(
			"public key in %q does not match private key in %q; "+
				"delete both files to trigger regeneration",
			pubPath, privPath,
		)
	}
	return priv, pub, nil
}

// writePrivateKey serialises key to PKCS#8 PEM and writes it with mode 0600.
func writePrivateKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal Ed25519 private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// writePublicKey serialises key to PKIX PEM and writes it with mode 0644.
func writePublicKey(path string, key ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644) //nolint:gosec // public key intended to be world-readable

}

// readPrivateKey parses a PKCS#8 PEM file and returns the Ed25519 private key.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key from %q: %w", path, err)
	}
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %q is not an Ed25519 private key (got %T)", path, raw)
	}
	return key, nil
}

// readPublicKey parses a PKIX PEM file and returns the Ed25519 public key.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key from %q: %w", path, err)
	}
	key, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %q is not an Ed25519 public key (got %T)", path, raw)
	}
	return key, nil
}

// ----- Refresh secret ---------------------------------------------------------

// loadOrGenerateRefreshSecret returns the HMAC key, generating and persisting
// it if the file does not exist.
func loadOrGenerateRefreshSecret(dir string, log logger) ([]byte, error) {
	path := filepath.Join(dir, fileRefreshSecret)

	if _, err := os.Stat(path); err == nil {
		log.Info("authcore/keymanager: loading existing refresh secret from %s", dir)
		return loadRefreshSecret(path)
	}

	log.Warn("authcore/keymanager: refresh secret not found, generating new secret in %s", dir)
	return generateAndSaveRefreshSecret(path)
}

// generateAndSaveRefreshSecret creates 32 bytes of CSPRNG output, hex-encodes
// it for human readability, and writes it to disk with mode 0600.
func generateAndSaveRefreshSecret(path string) ([]byte, error) {
	secret := make([]byte, refreshSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate refresh secret: %w", err)
	}
	// Hex-encode so the file survives editors that mangle binary content.
	content := hex.EncodeToString(secret) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return nil, fmt.Errorf("write refresh secret to %q: %w", path, err)
	}
	return secret, nil
}

// loadRefreshSecret reads, validates, and hex-decodes the secret file.
func loadRefreshSecret(path string) ([]byte, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read refresh secret from %q: %w", path, err)
	}
	hexStr := strings.TrimSpace(string(data))
	secret, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode refresh secret in %q: %w", path, err)
	}
	if len(secret) != refreshSecretLen {
		return nil, fmt.Errorf(
			"refresh secret in %q has wrong length: got %d bytes, want %d",
			path, len(secret), refreshSecretLen,
		)
	}
	return secret, nil
}
