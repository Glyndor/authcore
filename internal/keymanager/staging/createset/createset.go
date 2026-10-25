// Package createset generates a fresh key set into a private staging directory
// inside the key directory. It is the first half of the publish transaction;
// the staging root links the result into place (subpackage linkkeys).
package createset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// randRead is the source of randomness for staging directory names. It is
// exposed as a variable so a test can pin the name (the staging suffix is
// derived from CSPRNG output, and the staging path's collision behaviour is
// otherwise hard to exercise). Production callers must leave it pointing at
// rand.Read.
var randRead = rand.Read

// stagingDirName returns a fresh, randomised suffix for a staging directory.
// The dot keeps the directory hidden; 16 hex characters give 64 bits of
// collision resistance, which is enough for "no two concurrent initialisers
// pick the same name on the same KeysDir".
func stagingDirName() (string, error) {
	var b [8]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("generate staging suffix: %w", err)
	}
	return layout.StagingPrefix + hex.EncodeToString(b[:]), nil
}

// Discard removes a staging directory and the key files in it. It removes the
// entries one by one instead of calling os.RemoveAll, which has to open the
// parent directory for reading and so fails inside a KeysDir that can be
// written and searched but not read; that is exactly the directory in which
// the generation just failed. A failure is returned, never swallowed: what is
// left holds key material that was never published.
func Discard(staging string) error {
	var errs []error
	for _, name := range layout.KeyFileNames() {
		if err := os.Remove(filepath.Join(staging, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(staging); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("could not remove staging directory %q, which may hold key material that was never published; delete it: %w",
			staging, errors.Join(errs...))
	}
	return nil
}

// Create allocates a private staging directory inside KeysDir and
// writes the three key files into it with their final names and modes.
//
// KeysDir is synced before anything is created, so a directory that cannot be
// synced fails while there is nothing to clean up. The staging directory is
// created with os.Mkdir (not MkdirAll) at mode 0700; a name collision is an
// error rather than something to overwrite. A failure at any point removes the
// staging directory before returning so the caller never leaves a
// half-populated staging behind; if that removal fails too, the returned error
// says so and names the directory. On success the caller publishes the three
// files by hard-linking them into KeysDir.
func Create(dir string) (_ string, priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte, err error) {
	suffix, err := stagingDirName()
	if err != nil {
		return "", nil, nil, nil, err
	}
	if err := fileio.SyncDir(dir); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync keys directory: %w", err)
	}
	staging := filepath.Join(dir, suffix)
	if err := os.Mkdir(staging, 0700); err != nil {
		return "", nil, nil, nil, fmt.Errorf("create staging directory %q: %w", staging, err)
	}
	success := false
	defer func() {
		if !success {
			if derr := Discard(staging); derr != nil {
				err = errors.Join(err, derr)
			}
		}
	}()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("generate Ed25519 key pair: %w", err)
	}
	rsec := make([]byte, layout.RefreshSecretLen)
	if _, err := rand.Read(rsec); err != nil {
		return "", nil, nil, nil, fmt.Errorf("generate refresh secret: %w", err)
	}

	privPEM, err := pemcodec.EncodePrivateKeyPEM(edPriv)
	if err != nil {
		return "", nil, nil, nil, err
	}
	pubPEM, err := pemcodec.EncodePublicKeyPEM(edPub)
	if err != nil {
		return "", nil, nil, nil, err
	}
	// Hex-encode so the file survives editors that mangle binary content.
	// Keep the trailing newline the existing writer produces.
	secretHex := append([]byte(hex.EncodeToString(rsec)), '\n')

	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{layout.FilePrivateKey, privPEM, 0600},
		{layout.FilePublicKey, pubPEM, 0644}, //nolint:gosec // public key is intentionally world-readable
		{layout.FileRefreshSecret, secretHex, 0600},
	}
	for _, f := range files {
		if err := fileio.WriteKeyFile(filepath.Join(staging, f.name), f.data, f.perm); err != nil {
			return "", nil, nil, nil, fmt.Errorf("stage %q: %w", f.name, err)
		}
	}

	if err := fileio.SyncDir(staging); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync staging directory: %w", err)
	}
	if err := fileio.SyncDir(dir); err != nil {
		return "", nil, nil, nil, fmt.Errorf("sync keys directory: %w", err)
	}

	success = true
	return staging, edPriv, edPub, rsec, nil
}
