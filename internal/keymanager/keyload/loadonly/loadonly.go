// Load-only path for a pre-provisioned key directory.
//
// Config.RequireExistingKeys makes the disk store refuse to start unless the
// three key files are already in place. This file owns the matching entry
// point: a function that reads the directory and never writes anything to it.
// It exists separately from New because New's contract includes generating
// the set when none is there, and that contract is what RequireExistingKeys
// turns off. Reusing New would have left the mkdir, the gitignore and the
// metadata-write code reachable on the same call.

// Package loadonly reads a pre-provisioned key directory without ever writing
// to it: the entry point behind Config.RequireExistingKeys.
package loadonly

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
	"github.com/Glyndor/authcore/internal/keymanager/modecheck"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/leftovers"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

// Load reads an existing key set from dir and returns the keys it holds.
//
// It performs no writes of any kind: no MkdirAll, no directory chmod, no
// .gitignore, no metadata creation or refresh, no staging directory, no
// hard-link. Its purpose is the production deploy that mounts the keys as a
// read-only Secret and must be able to start without ever producing a
// filesystem event in that mount.
//
// Behaviour:
//
//   - dir must exist as a directory; os.Stat follows symlinks, which a
//     Kubernetes Secret mount depends on. A missing path or a non-directory
//     entry returns an error that names dir and lists the three filenames a
//     complete set needs.
//   - metadata.json, when present, is read with metadata.Read; a missing file
//     is fine (the pre-metadata layout is adopted), and any other failure of
//     metadata.Read (unparseable content, a future format) is returned
//     verbatim, because the directory is not being written here.
//   - The three key files must all be present. Any missing file produces an
//     error that lists present and missing filenames and tells the operator
//     to restore the missing files from a backup. The wording names the
//     danger of regenerating refresh_secret.key.
//   - The files are loaded and validated through loadEd25519 and
//     loadRefreshSecret, the same functions New uses on the complete path:
//     size-cap, PEM parse, pair-consistency and secret-length checks all
//     apply, so a directory that passed a previous Load or New is loaded
//     identically here.
//   - leftovers.Report runs once before return: it is the read-only scan that
//     warns about stale staging directories, and no operation here depends
//     on it having been run.
//
// All errors returned here are wrapped by the disk store in keystore.go,
// which itself wraps ErrKeyManager around them.
func Load(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, refusals.MissingDir(dir)
		}
		return nil, nil, nil, fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, nil, nil, fmt.Errorf(
			"key directory %q is a %s, not a directory; authcore must be able to read "+
				"the three key files (ed25519_private.pem, ed25519_public.pem, "+
				"refresh_secret.key) from it before it will start",
			dir, fi.Mode().Type())
	}

	// Load reads metadata only to surface read errors; it never writes it.
	if _, err := metadata.Read(dir); err != nil {
		return nil, nil, nil, err
	}

	state, err := fsguard.InspectKeySet(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if state != fsguard.SetComplete {
		present, missing := fsguard.PresentAndMissing(dir)
		return nil, nil, nil, refusals.IncompleteLoad(dir, present, missing)
	}

	priv, pub, secret, err := keyload.Files(dir, log)
	if err != nil {
		return nil, nil, nil, err
	}

	// The load-only path also reports a key directory others can write to; New
	// tightens it instead.
	modecheck.WarnIfDirWritableByOthers(dir, log)

	leftovers.Report(dir, log)
	return priv, pub, secret, nil
}
