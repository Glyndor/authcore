// Package keyload reads a key set back from disk: the Ed25519 pair, checked
// for consistency, and the hex-encoded refresh secret, checked for length and for the patterns no random value has. Every
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
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// ----- Ed25519 key pair -------------------------------------------------------

// loadEd25519 reads and validates an Ed25519 key pair from disk.
func loadEd25519(privPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privData, err := fileio.ReadCapped(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}
	pubData, err := fileio.ReadCapped(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load public key: %w", err)
	}
	return decodeEd25519(privData, pubData, privPath, pubPath)
}

// decodeEd25519 parses and validates a key pair from the bytes of its two
// files. The paths are only used in messages.
func decodeEd25519(privData, pubData []byte, privPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	priv, err := pemcodec.DecodeEd25519PrivatePEM(privData, privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}
	if err := material.CheckSeed(priv); err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}
	pub, err := pemcodec.DecodeEd25519PublicPEM(pubData, pubPath)
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

// ----- Refresh secret ---------------------------------------------------------

// loadRefreshSecret reads, validates, and hex-decodes the secret file.
func loadRefreshSecret(path string) ([]byte, error) {
	data, err := fileio.ReadCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read refresh secret from %q: %w", path, err)
	}
	return decodeRefreshSecret(data, path)
}

// decodeRefreshSecret validates and hex-decodes the bytes of the secret file.
// path is only used in messages.
func decodeRefreshSecret(data []byte, path string) ([]byte, error) {
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
	if err := material.CheckSecret(secret); err != nil {
		return nil, err
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
