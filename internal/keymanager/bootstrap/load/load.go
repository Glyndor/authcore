// Package load is the complete-directory half of bootstrap.Open: it validates the
// key files already on disk, syncs the metadata and reports leftovers.
package load

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/leftovers"
)

// FromKeysDir is the complete-directory path: load the three files
// through the existing validators (which check pair consistency and secret
// length), sync metadata, and report any leftover staging directories.
//
// The loading path tolerates a read-only KeysDir: symlinks are followed by
// os.Stat, the size cap is honoured, and metadata is written with a warning
// rather than as an error.
func FromKeysDir(dir string, meta *metadata.Metadata, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	priv, pub, secret, err := keyload.Files(dir, log)
	if err != nil {
		return nil, nil, nil, err
	}

	keyID := material.KeyID(pub)
	if err := metadata.Sync(dir, meta, keyID, log); err != nil {
		return nil, nil, nil, err
	}
	if err := fileio.SyncDir(dir); err != nil {
		// A read-only KeysDir (a mounted secret) is a supported deployment;
		// the metadata is already written when possible, so a sync that
		// cannot flush is a warning, not a load failure.
		log.Warn("authcore/keymanager: could not sync key directory %q (continuing): %v", dir, err)
	}
	leftovers.Report(dir, log)
	return priv, pub, secret, nil
}
