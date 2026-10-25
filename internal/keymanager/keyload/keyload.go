// Package keyload reads a key set back from disk: the Ed25519 pair, checked
// for consistency, and the hex-encoded refresh secret, checked for length. Every
// read is size-capped and nothing here ever writes.
package keyload

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/modecheck"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// ----- Ed25519 key pair -------------------------------------------------------

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
				"restore the matching pair from a backup",
			pubPath, privPath,
		)
	}
	return priv, pub, nil
}

// readPrivateKey parses a PKCS#8 PEM file and returns the Ed25519 private key.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := fileio.ReadCapped(path)
	if err != nil {
		return nil, err
	}
	return pemcodec.DecodeEd25519PrivatePEM(data, path)
}

// readPublicKey parses a PKIX PEM file and returns the Ed25519 public key.
func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := fileio.ReadCapped(path)
	if err != nil {
		return nil, err
	}
	return pemcodec.DecodeEd25519PublicPEM(data, path)
}

// ----- Refresh secret ---------------------------------------------------------

// loadRefreshSecret reads, validates, and hex-decodes the secret file.
func loadRefreshSecret(path string) ([]byte, error) {
	data, err := fileio.ReadCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read refresh secret from %q: %w", path, err)
	}
	hexStr := strings.TrimSpace(string(data))
	secret, err := hex.DecodeString(hexStr)
	if err != nil {
		// Not %w: the hex error quotes the offending byte, which is a byte
		// of the secret, and this message ends up in a log.
		return nil, fmt.Errorf("refresh secret in %q is not hex encoded", path)
	}
	if len(secret) != layout.RefreshSecretLen {
		return nil, fmt.Errorf(
			"refresh secret in %q has wrong length: got %d bytes, want %d",
			path, len(secret), layout.RefreshSecretLen,
		)
	}
	return secret, nil
}

// Check reports whether dir holds a consistent key set: a private key, the
// public key that belongs to it and a well-formed refresh secret. It reads the
// files and warns about nothing, so a staged set can be judged before any of it
// is linked into KeysDir.
func Check(dir string) error {
	if _, _, err := loadEd25519(filepath.Join(dir, layout.FilePrivateKey), filepath.Join(dir, layout.FilePublicKey)); err != nil {
		return fmt.Errorf("ed25519 key pair: %w", err)
	}
	if _, err := loadRefreshSecret(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		return fmt.Errorf("refresh secret: %w", err)
	}
	return nil
}

// Files loads the three key files from dir through the validators above:
// size cap, PEM parse, pair consistency and secret length all apply. It warns,
// without ever refusing or changing a mode, when the private key or the refresh
// secret is readable by group or others.
//
// The loading path tolerates a read-only KeysDir: symlinks are followed by
// os.Stat and the size cap is honoured.
func Files(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	privPath := filepath.Join(dir, layout.FilePrivateKey)
	pubPath := filepath.Join(dir, layout.FilePublicKey)
	secretPath := filepath.Join(dir, layout.FileRefreshSecret)

	priv, pub, err := loadEd25519(privPath, pubPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ed25519 key pair: %w", err)
	}
	secret, err := loadRefreshSecret(secretPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("refresh secret: %w", err)
	}

	// Warn (never refuse, never chmod) when the private key or the refresh
	// secret is readable by group or others. The public key is omitted by
	// design: it is meant to be shared, so the same bit pattern on it is
	// not a finding.
	modecheck.WarnIfReadableByOthers(privPath, log)
	modecheck.WarnIfReadableByOthers(secretPath, log)
	return priv, pub, secret, nil
}
