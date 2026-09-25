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
//	metadata.json        — on-disk layout version, mode 0600
//
// On subsequent calls the existing files are loaded and validated; no new
// material is generated unless a file is missing.
//
// metadata.json records which layout wrote the directory, so a future release
// that changes the on-disk format can migrate what is there instead of
// regenerating it — regenerating would invalidate every refresh-token and
// API-key hash the consumer has stored, logging out all of their users. A
// directory written before this file existed carries no marker; it is adopted
// in place, keys untouched. A directory reporting a newer format is refused
// rather than parsed on a guess.
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
	"errors"
	"fmt"
	"io/fs"
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
	dir   string
	keyID string
	// material is a pointer on purpose. fmt prints a pointer it meets inside a
	// struct as an address, except on a verb pointers do not support (%s, %q,
	// %t, ...), where it dereferences one level. A *KeyManager held in an
	// unexported field of AuthCore or of an in-memory KeyStore bypasses its
	// Format method, so until 2026-09-25 log.Printf("%s", auth) printed the
	// private key and refresh secret. One more level of indirection stops fmt
	// at an address.
	material *secretMaterial
}

// secretMaterial is the key set a KeyManager holds. The public key lives here
// too so the three values are replaced together.
type secretMaterial struct {
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	refreshSecret []byte
}

// New initialises the KeyManager for the given directory.
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
// dir is used verbatim: New does not append ".authcore" or any other
// subdirectory, and Dir returns the value as passed in (no resolution to
// an absolute path). Callers who want the keys inside a ".authcore"
// subdirectory must pass ".authcore" explicitly.
func New(dir string, log logger) (*KeyManager, error) {
	if _, err := os.Stat(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create key directory %q: %w", dir, err)
	}

	// MkdirAll does not tighten a directory that already exists, so a pre-created
	// or volume-mounted KeysDir could sit at a looser mode (e.g. 0755). Tighten
	// it to owner-only — but only ever tighten. An operator who hands over a
	// stricter directory (0500 for a read-only mounted secret) means it, and
	// widening the permissions on the directory that holds the private key would
	// be the opposite of what this exists for. A failure here is not fatal — the
	// private key and refresh secret are still written 0600 — so warn rather than
	// abort.
	if err := tightenDirMode(dir); err != nil {
		log.Warn("authcore/keymanager: could not tighten key directory %q to %o: %v", dir, dirMode, err)
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
	meta, err := readMetadata(dir)
	if err != nil {
		return nil, err
	}

	state, err := inspectKeySet(dir)
	if err != nil {
		return nil, err
	}

	if state == setEmpty {
		// metadata.json is written only after a key set is published, so its
		// presence with no key files left means a set existed and is gone.
		// Until 2026-09-25 New generated a fresh set here and then rewrote
		// the recorded key id, erasing the one sign of what was lost.
		if meta != nil {
			return nil, refuseRegeneration(dir, meta)
		}
		if err := symlinkPreflight(dir); err != nil {
			return nil, err
		}
		return newByStaging(dir, meta, log)
	}

	if state == setPartial {
		if err := recoverPartial(dir, log); err != nil {
			return nil, err
		}
	}
	return loadFromKeysDir(dir, meta, log)
}

// setState names whether KeysDir is empty, partial, or complete. The empty
// case takes the staging path; the complete case loads; the partial case
// recovers (or refuses).
type setState int

const (
	setEmpty setState = iota
	setPartial
	setComplete
)

// inspectKeySet counts how many of the three managed key files are present
// in dir as regular files (or symlinks to regular files, since reads follow).
// A classification error (a symlink loop or hostile entry) is surfaced as an
// error: ignoring it would let New either write beside it or load from it.
func inspectKeySet(dir string) (setState, error) {
	present := 0
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		state, err := inspect(dir, name)
		if err != nil {
			return 0, err
		}
		if state != fileAbsent {
			present++
		}
	}
	switch {
	case present == 0:
		return setEmpty, nil
	case present == 3:
		return setComplete, nil
	default:
		return setPartial, nil
	}
}

// newByStaging is the empty-directory path: generate a key set into a private
// staging directory, hard-link the three files into KeysDir, then write
// metadata atomically. The in-memory keys are returned directly so the loaders
// are not invoked on bytes we just wrote.
func newByStaging(dir string, meta *metadata, log logger) (*KeyManager, error) {
	// Warn before any fresh material is generated. The reason is the one in
	// docs/key-management.md: an empty KeysDir on a container recreation, or
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
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return nil, fmt.Errorf("sync parent of keys directory: %w", err)
	}
	staging, priv, pub, secret, err := createStagingSet(dir)
	if err != nil {
		return nil, err
	}
	if err := faultAt("staged"); err != nil {
		return nil, err
	}
	if err := linkKeys(dir, staging, log); err != nil {
		if errors.Is(err, errWaitAndLoad) {
			if werr := waitForSet(dir, log); werr != nil {
				return nil, werr
			}
			return loadFromKeysDir(dir, meta, log)
		}
		return nil, err
	}
	keyID := computeKeyID(pub)
	if err := syncMetadata(dir, meta, keyID, log); err != nil {
		return nil, err
	}
	reportLeftovers(dir, log)
	return &KeyManager{
		dir:      dir,
		material: &secretMaterial{privateKey: priv, publicKey: pub, refreshSecret: secret},
		keyID:    keyID,
	}, nil
}

// loadFromKeysDir is the complete-directory path: load the three files
// through the existing validators (which check pair consistency and secret
// length), sync metadata, and report any leftover staging directories.
//
// The loading path tolerates a read-only KeysDir: symlinks are followed by
// os.Stat, the size cap is honoured, and metadata is written with a warning
// rather than as an error.
func loadFromKeysDir(dir string, meta *metadata, log logger) (*KeyManager, error) {
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

	keyID := computeKeyID(pub)
	if err := syncMetadata(dir, meta, keyID, log); err != nil {
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		// A read-only KeysDir (a mounted secret) is a supported deployment;
		// the metadata is already written when possible, so a sync that
		// cannot flush is a warning, not a load failure.
		log.Warn("authcore/keymanager: could not sync key directory %q (continuing): %v", dir, err)
	}
	reportLeftovers(dir, log)
	return &KeyManager{
		dir:      dir,
		material: &secretMaterial{privateKey: priv, publicKey: pub, refreshSecret: secret},
		keyID:    keyID,
	}, nil
}

// KeyID derives the stable key identifier for pub — the same value a
// KeyManager reports for its own key. It is exported so the JWT module can
// index additional verification keys (during rotation) by the same id without
// duplicating the derivation.
func KeyID(pub ed25519.PublicKey) string { return computeKeyID(pub) }

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
	return km.material.privateKey
}

// PublicKey returns the Ed25519 public key used for signature verification.
// The returned slice must not be modified by the caller.
func (km *KeyManager) PublicKey() ed25519.PublicKey {
	return km.material.publicKey
}

// RefreshSecret returns the 32-byte secret used as the HMAC-SHA256 key when
// hashing refresh tokens (and, in the apikey module, as the key-hash pepper).
// The returned slice must not be modified by the caller.
//
// The secret is intentionally shared across those uses. HMAC-SHA256 is a secure
// PRF under multi-purpose use and the message namespaces differ (a compact JWT
// vs an "ak_<id>_<secret>" key), so there is no cross-protocol forgery. It is
// not split into per-use subkeys (e.g. via HKDF) because the resulting hashes
// are stored by the consumer: changing the derivation would invalidate every
// stored refresh-token and API-key hash on upgrade, forcing all users to
// re-authenticate — a breaking change the library avoids by design.
func (km *KeyManager) RefreshSecret() []byte {
	return km.material.refreshSecret
}

// KeyID returns the stable identifier for the current signing key.
// See computeKeyID for the derivation details.
func (km *KeyManager) KeyID() string {
	return km.keyID
}

// Dir returns the value passed to New, verbatim. No resolution to an
// absolute path is performed; a relative argument is returned as given.
func (km *KeyManager) Dir() string {
	return km.dir
}

// tightenDirMode removes any permission bit outside dirMode from dir, and
// leaves a directory that is already at or below dirMode untouched.
//
// Chmodding unconditionally would also *raise* a stricter mode to 0700, which
// is why the current mode is read first: 0755 becomes 0700, while 0500 stays
// 0500. On a platform without Unix permission bits the mode carries no group
// or world bits to strip, so this is a no-op there.
func tightenDirMode(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	mode := fi.Mode().Perm()
	if mode&^dirMode == 0 {
		return nil // already at least this strict
	}
	return os.Chmod(dir, mode&dirMode)
}

// ensureGitignore writes a catch-all .gitignore inside dir if one does
// not already exist. It is idempotent.
func ensureGitignore(dir string) error {
	path := filepath.Join(dir, fileGitignore)
	if exists(dir, fileGitignore) {
		return nil // already present
	}
	return createExclusive(path, []byte(gitignoreContent), 0600)
}
