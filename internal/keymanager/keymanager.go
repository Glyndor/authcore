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

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/keyload/loadonly"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// logger is the minimal logging dependency for the key manager.
// It is intentionally unexported and narrow.
// Any authcore.Logger value satisfies it via Go's structural typing.
type logger = layout.Logger

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
// dir must not be a symbolic link: New refuses it before creating, tightening
// or writing anything. Links in its parent components are not refused.
//
// dir is used verbatim: New does not append ".authcore" or any other
// subdirectory, and Dir returns the value as passed in (no resolution to
// an absolute path). Callers who want the keys inside a ".authcore"
// subdirectory must pass ".authcore" explicitly.
func New(dir string, log logger) (*KeyManager, error) {
	priv, pub, secret, err := bootstrap.Open(dir, log)
	if err != nil {
		return nil, err
	}
	return newKeyManager(dir, priv, pub, secret), nil
}

// newKeyManager wraps keys that were just loaded or generated from dir.
func newKeyManager(dir string, priv ed25519.PrivateKey, pub ed25519.PublicKey, secret []byte) *KeyManager {
	return &KeyManager{
		dir:      dir,
		material: &secretMaterial{privateKey: priv, publicKey: pub, refreshSecret: secret},
		keyID:    material.KeyID(pub),
	}
}

// KeyID derives the stable key identifier for pub — the same value a
// KeyManager reports for its own key. It is exported so the JWT module can
// index additional verification keys (during rotation) by the same id without
// duplicating the derivation.
func KeyID(pub ed25519.PublicKey) string { return material.KeyID(pub) }

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
// See material.KeyID for the derivation details.
func (km *KeyManager) KeyID() string {
	return km.keyID
}

// Dir returns the value passed to New, verbatim. No resolution to an
// absolute path is performed; a relative argument is returned as given.
func (km *KeyManager) Dir() string {
	return km.dir
}

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
//   - dir must not be a symbolic link itself (its parent components may be);
//     the files inside it may be links, which a Kubernetes Secret mount
//     depends on.
//   - dir must exist as a directory. A missing path or a non-directory
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
	priv, pub, secret, err := loadonly.Load(dir, log)
	if err != nil {
		return nil, err
	}
	return newKeyManager(dir, priv, pub, secret), nil
}

// DecodePEMBlock returns the DER bytes of the one PEM block in data, which
// must be labelled wantType, carry no headers, and be the only thing in data
// apart from whitespace. pem.Decode alone returns the first block wherever
// it sits and ignores the label, the headers and whatever follows, so a file
// holding two keys signed with whichever came first, and a PKCS#8 key under a
// CERTIFICATE label or behind Proc-Type headers was accepted (measured
// 2026-09-25). Key material has one canonical shape here.
func DecodePEMBlock(data []byte, wantType, src string) ([]byte, error) {
	return pemcodec.DecodePEMBlock(data, wantType, src)
}
