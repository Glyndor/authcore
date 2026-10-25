// Package generate is the empty-directory half of bootstrap.Open: it writes a
// fresh key set through a staging directory, publishes it, and records the
// metadata. A loser of the publish race falls through to the load package.
package generate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/load"
	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/leftovers"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/wait"
	"github.com/Glyndor/authcore/internal/keymanager/staging"
)

// Fresh is the empty-directory path: generate a key set into a private
// staging directory, hard-link the three files into KeysDir, then write
// metadata atomically. The in-memory keys are returned directly so the loaders
// are not invoked on bytes we just wrote.
func Fresh(dir string, meta *metadata.Metadata, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	// Warn before any fresh material is generated. The reason is the one in
	// docs/guides/key-management.md: an empty KeysDir on a container recreation, or
	// on a fresh volume, means every issued token, every stored refresh-token
	// hash, and every auth/field encrypted column is about to become
	// unrecognised. Operators wire this Warn into monitoring so they find out
	// before users do.
	log.Warn("authcore/keymanager: KeysDir %q is empty; generating a fresh key "+
		"set, which invalidates every issued token, every stored refresh-token "+
		"and API-key hash, and every auth/field encrypted column",
		dir)

	// Sync the parent directory before the first publish. Another process
	// may have created KeysDir without syncing its parent entry yet, and
	// this process is about to publish keys that other processes will use.
	if err := fileio.SyncDir(filepath.Dir(dir)); err != nil {
		// A parent with search but no read permission (0711, 0311) cannot be
		// opened for fsync, and nothing here needs to read it. The load path
		// treats the same sync as best effort; so does this one since
		// 2026-09-25. Any other failure still stops the first run.
		if errors.Is(err, fs.ErrPermission) {
			log.Warn("authcore/keymanager: could not sync the parent of %q (continuing): %v", dir, err)
		} else {
			return nil, nil, nil, fmt.Errorf("sync parent of keys directory: %w", err)
		}
	}
	priv, pub, secret, err := staging.Publish(dir, log)
	if err != nil {
		if errors.Is(err, staging.ErrWaitAndLoad) {
			if werr := wait.ForSet(dir, log); werr != nil {
				return nil, nil, nil, werr
			}
			return load.FromKeysDir(dir, meta, log)
		}
		return nil, nil, nil, err
	}
	keyID := material.KeyID(pub)
	if err := metadata.Sync(dir, meta, keyID, log); err != nil {
		return nil, nil, nil, err
	}
	leftovers.Report(dir, log)
	return priv, pub, secret, nil
}
