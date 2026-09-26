// Load-only path for a pre-provisioned key directory.
//
// Config.RequireExistingKeys makes the disk store refuse to start unless the
// three key files are already in place. This file owns the matching entry
// point: a function that reads the directory and never writes anything to it.
// It exists separately from New because New's contract includes generating
// the set when none is there, and that contract is what RequireExistingKeys
// turns off. Reusing New would have left the mkdir, the gitignore and the
// metadata-write code reachable on the same call.

package keymanager

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Load reads an existing key set from dir and returns a *KeyManager holding it.
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
//   - metadata.json, when present, is read with readMetadata; a missing file
//     is fine (the pre-metadata layout is adopted), and any other failure of
//     readMetadata (unparseable content, a future format) is returned
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
//   - reportLeftovers runs once before return: it is the read-only scan that
//     warns about stale staging directories, and no operation here depends
//     on it having been run.
//
// All errors returned here are wrapped by the disk store in keystore.go,
// which itself wraps ErrKeyManager around them.
func Load(dir string, log logger) (*KeyManager, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, missingDirError(dir)
		}
		return nil, fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf(
			"key directory %q is a %s, not a directory; authcore must be able to read "+
				"the three key files (ed25519_private.pem, ed25519_public.pem, "+
				"refresh_secret.key) from it before it will start",
			dir, fi.Mode().Type())
	}

	// Load reads metadata only to surface read errors; it never writes it.
	if _, err := readMetadata(dir); err != nil {
		return nil, err
	}

	state, err := inspectKeySet(dir)
	if err != nil {
		return nil, err
	}
	if state != setComplete {
		present, missing := presentAndMissing(dir)
		return nil, refuseIncompleteLoad(dir, present, missing)
	}

	privPath := filepath.Join(dir, filePrivateKey)
	pubPath := filepath.Join(dir, filePublicKey)
	secretPath := filepath.Join(dir, fileRefreshSecret)

	priv, pub, err := loadEd25519(privPath, pubPath)
	if err != nil {
		return nil, fmt.Errorf("ed25519 key pair: %w", err)
	}
	secret, err := loadRefreshSecret(secretPath)
	if err != nil {
		return nil, fmt.Errorf("refresh secret: %w", err)
	}

	// Warn (never refuse, never chmod) when the private key or the refresh
	// secret is readable by group or others. The public key is omitted by
	// design: it is meant to be shared, so the same bit pattern on it is
	// not a finding.
	warnIfReadableByOthers(privPath, log)
	warnIfReadableByOthers(secretPath, log)
	warnIfDirWritableByOthers(dir, log)

	keyID := computeKeyID(pub)
	reportLeftovers(dir, log)

	return &KeyManager{
		dir:      dir,
		material: &secretMaterial{privateKey: priv, publicKey: pub, refreshSecret: secret},
		keyID:    keyID,
	}, nil
}

// missingDirError returns the message a load-only deploy should see when dir
// is unreachable. The wording names the path and the three files a complete
// set has, and is what an operator running `podman volume ls` next needs to
// read.
func missingDirError(dir string) error {
	return fmt.Errorf(
		"key directory %q does not exist; authcore will not generate keys in "+
			"load-only mode. Provision ed25519_private.pem, ed25519_public.pem "+
			"and refresh_secret.key (restore them from a backup, or generate "+
			"them once without Config.RequireExistingKeys set) before starting",
		dir)
}

// refuseIncompleteLoad reports a KeysDir that does not hold all three key
// files. The wording lists present and missing files, tells the operator to
// restore the missing ones from a backup, and repeats why refresh_secret.key
// must not be regenerated: deleting or regenerating it invalidates every
// stored refresh-token hash, API-key hash and auth/field column.
func refuseIncompleteLoad(dir string, present, missing []string) error {
	presentStr := "none"
	if len(present) > 0 {
		presentStr = strings.Join(present, ", ")
	}
	missingStr := "none"
	if len(missing) > 0 {
		missingStr = strings.Join(missing, ", ")
	}
	return fmt.Errorf(
		"key directory %q is not complete in load-only mode: present {%s}, missing {%s}; "+
			"restore the missing file(s) from a backup; refresh_secret.key must "+
			"not be regenerated because every stored refresh-token hash, "+
			"API-key hash and every auth/field encrypted column depends on it",
		dir, presentStr, missingStr)
}
