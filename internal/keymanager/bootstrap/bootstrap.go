// Package bootstrap is the orchestration behind keymanager.New: it prepares the
// key directory, reads the layout marker, and then either generates a fresh key
// set, recovers a partial one, or loads a complete one.
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/generate"
	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/load"
	"github.com/Glyndor/authcore/internal/keymanager/dirguard"
	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
	"github.com/Glyndor/authcore/internal/keymanager/modecheck"
	"github.com/Glyndor/authcore/internal/keymanager/recovery"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/staging/preflight"
)

// Open initialises the key directory and returns the key set it holds.
//
// It creates the directory if it does not exist, writes a protective
// .gitignore, then either loads an existing key set or generates a new one
// as a single, recoverable transaction.
//
// An empty directory receives a staging directory at .staging-<random hex>,
// the three key files are written and fsynced there, then hard-linked into
// the final names in the fixed order private, public, refresh-secret. A
// concurrent initialiser that loses the race to the private link waits for
// the winner to finish and loads the same keys; it never regenerates.
//
// A partially-populated directory (some files present, some missing) is
// recovered by finding a matching .staging-* whose private key matches the
// published one and linking the missing files. A partial set with no
// matching staging directory is refused with advice that never asks the
// operator to delete refresh_secret.key.
//
// dir must not be a symbolic link: Open refuses it before creating, tightening
// or writing anything. Links in its parent components are not refused.
//
// dir is used verbatim: Open does not append ".authcore" or any other
// subdirectory.
func Open(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	// Nothing below runs until the path is known to name the directory itself:
	// MkdirAll, the chmod and every write would otherwise follow a link.
	if err := dirguard.Refuse(dir); err != nil {
		return nil, nil, nil, err
	}
	if _, err := os.Stat(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if err := os.MkdirAll(dir, layout.DirMode); err != nil {
		return nil, nil, nil, fmt.Errorf("create key directory %q: %w", dir, err)
	}

	// MkdirAll does not tighten a directory that already exists, so a pre-created
	// or volume-mounted KeysDir could sit at a looser mode (e.g. 0755). Tighten
	// it to owner-only — but only ever tighten. An operator who hands over a
	// stricter directory (0500 for a read-only mounted secret) means it, and
	// widening the permissions on the directory that holds the private key would
	// be the opposite of what this exists for. A failure here is not fatal — the
	// private key and refresh secret are still written 0600 — so warn rather than
	// abort.
	if err := modecheck.TightenDirMode(dir); err != nil {
		log.Warn("authcore/keymanager: could not tighten key directory %q to %o: %v", dir, layout.DirMode, err)
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
	meta, err := metadata.Read(dir)
	if err != nil {
		return nil, nil, nil, err
	}

	state, err := fsguard.InspectKeySet(dir)
	if err != nil {
		return nil, nil, nil, err
	}

	if state == fsguard.SetEmpty {
		// metadata.json is written only after a key set is published, so its
		// presence with no key files left means a set existed and is gone.
		// Until 2026-09-25 New generated a fresh set here and then rewrote
		// the recorded key id, erasing the one sign of what was lost.
		if meta != nil {
			return nil, nil, nil, refusals.Regeneration(dir, meta.KeyID)
		}
		if err := preflight.Symlinks(dir); err != nil {
			return nil, nil, nil, err
		}
		return generate.Fresh(dir, meta, log)
	}

	if state == fsguard.SetPartial {
		if err := recovery.RecoverPartial(dir, log); err != nil {
			return nil, nil, nil, err
		}
	}
	return load.FromKeysDir(dir, meta, log)
}

// ensureGitignore writes a catch-all .gitignore inside dir if one does
// not already exist. It is idempotent.
func ensureGitignore(dir string) error {
	path := filepath.Join(dir, layout.FileGitignore)
	if fsguard.Exists(dir, layout.FileGitignore) {
		return nil // already present
	}
	return fsguard.CreateExclusive(path, []byte(layout.GitignoreContent), 0600)
}
