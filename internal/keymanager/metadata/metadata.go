// Package metadata reads and writes metadata.json, the marker that records
// which on-disk layout wrote a key directory, so that a future release can
// migrate what is there instead of regenerating it.
package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/binding"
	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// CurrentFormat is the version of the on-disk layout this build writes and
// understands. Bump it only when the meaning of an existing file changes —
// adding a new file that older versions simply ignore does not need a bump.
const CurrentFormat = 1

// Metadata is the content of layout.FileMetadata. It holds no secret — KeyID is
// derived from the public key and already travels in every JWT header, and
// SecretBinding is a keyed hash that reveals nothing of the key it is keyed
// with — but it is written 0600 anyway, since nothing outside authcore reads it.
type Metadata struct {
	// Format is the on-disk layout version. A directory written by a newer
	// authcore carries a higher number and is refused rather than guessed at.
	Format int `json:"format"`
	// Created is when the key material was first written, RFC 3339. For a
	// directory adopted from the pre-metadata layout it is the modification
	// time of the private key, which is the closest honest answer available.
	Created string `json:"created"`
	// KeyID identifies the signing key that was live when this file was last
	// written. It is informational: it lets an operator see which key a
	// directory holds without parsing the PEM.
	KeyID string `json:"key_id"`
	// SecretBinding ties refresh_secret.key to the key pair (see package
	// binding). It is absent in a directory written before it existed; the
	// next start records it in place. Releases that predate it ignore the
	// field, so a directory migrated by this build still loads in them.
	SecretBinding string `json:"secret_binding,omitempty"`
}

// ErrFormatFromFuture reports a directory written by a newer authcore.
var ErrFormatFromFuture = errors.New("key directory was written by a newer version of authcore")

// Read loads the descriptor from dir.
//
// A missing file is not an error: it means the pre-metadata layout, and the
// caller adopts it. Anything else — unreadable, malformed, or a format this
// build does not understand — is fatal, because the whole point of the marker
// is to stop a loader from guessing at key material it may not understand.
func Read(dir string) (*Metadata, error) {
	path := filepath.Join(dir, layout.FileMetadata)

	// The key files are refused unless they are regular files; the marker
	// was opened without that check, so a FIFO here blocked New and Load in
	// open forever (measured 2026-09-25).
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is a %s, not a regular file; authcore refuses to read it as the key layout marker",
			path, fi.Mode().Type())
	}

	data, err := fileio.ReadCapped(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // pre-metadata layout
		}
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf(
			"parse %q: %w; the file describes the key layout and holds no key material, "+
				"so deleting it is safe and makes authcore re-adopt the existing keys",
			path, err,
		)
	}

	if m.Format > CurrentFormat {
		return nil, fmt.Errorf(
			"%w: %q reports format %d, this build understands %d; upgrade authcore rather than downgrading the directory",
			ErrFormatFromFuture, path, m.Format, CurrentFormat,
		)
	}
	if m.Format < 1 {
		return nil, fmt.Errorf("%q reports an invalid format %d", path, m.Format)
	}

	return &m, nil
}

// Sync brings the descriptor in line with the keys that were just
// loaded or generated: it writes one for a directory that has none (adopting
// the pre-metadata layout in place, without touching the keys), refreshes the
// recorded key id and secret binding when the signing key has been rotated
// underneath, and records the binding on a descriptor that predates it.
//
// A genuine write failure is reported to the log and not returned: the
// descriptor is bookkeeping and a read-only KeysDir (a mounted secret) is a
// supported deployment, so a metadata write that fails must not stop a
// service from starting. A faultAt return is a test-only signal and is
// returned verbatim so the publish transaction aborts as a crash would.
func Sync(dir string, existing *Metadata, keyID, secretBinding string, log layout.Logger) error {
	switch {
	case existing == nil:
		m := Metadata{
			Format:  CurrentFormat,
			Created: creationTime(dir),
			KeyID:   keyID,

			SecretBinding: secretBinding,
		}
		if err := write(dir, m); err != nil {
			log.Warn("authcore/keymanager: could not write %s in %q (continuing): %v", layout.FileMetadata, dir, err)
			return nil
		}
		if err := seams.Fault("metadata-written"); err != nil {
			return err
		}
		log.Info("authcore/keymanager: recorded on-disk format %d for %s", CurrentFormat, dir)

	case existing.KeyID != keyID:
		// The signing key changed since the descriptor was written — a manual
		// rotation, or keys restored from elsewhere. Follow the keys.
		m := *existing
		m.KeyID = keyID
		m.SecretBinding = secretBinding
		if err := write(dir, m); err != nil {
			log.Warn("authcore/keymanager: could not update %s in %q (continuing): %v", layout.FileMetadata, dir, err)
			return nil
		}
		if err := seams.Fault("metadata-written"); err != nil {
			return err
		}
		log.Info("authcore/keymanager: signing key changed, %s now records key id %s", layout.FileMetadata, keyID)

	case existing.SecretBinding == "":
		// A directory written before the binding existed: bind its secret to
		// its key pair in place. Keys and secret are untouched, so nothing
		// issued so far stops verifying.
		m := *existing
		m.SecretBinding = secretBinding
		if err := write(dir, m); err != nil {
			log.Warn("authcore/keymanager: could not update %s in %q (continuing): %v", layout.FileMetadata, dir, err)
			return nil
		}
		if err := seams.Fault("metadata-written"); err != nil {
			return err
		}
		log.Info("authcore/keymanager: recorded the refresh secret binding in %s", layout.FileMetadata)
	}
	return nil
}

// CheckSecret refuses a refresh secret that is not the one recorded for the
// key pair. It checks only a descriptor that was written for this very
// signing key and already carries a binding; a rotated key id is handled by
// Sync, and a descriptor without a binding is adopted by it.
func CheckSecret(dir string, m *Metadata, pub ed25519.PublicKey, secret []byte) error {
	if m == nil || m.SecretBinding == "" || m.KeyID != material.KeyID(pub) {
		return nil
	}
	if binding.Matches(m.SecretBinding, pub, secret) {
		return nil
	}
	return refusals.SecretMismatch(dir)
}

// write serialises m into dir atomically.
//
// The file is written to a random-named temp sibling, fsynced, then renamed
// onto metadata.json. The rename is the commit; on a crash mid-write, the
// previous metadata.json (or its absence) is preserved and the temp file is
// left behind for the operator to inspect or remove. A second crash between
// the rename and the directory sync could still see the new metadata as
// unpublished, but the previous metadata.json is what Read would have
// returned; the worst case is a one-startup delay, not a torn file.
//
// Sync wraps this so failures stay warnings and never block startup;
// write itself returns errors because the metadata tests pin them.
func write(dir string, m Metadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", layout.FileMetadata, err)
	}
	data = append(data, '\n')

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Errorf("generate metadata temp suffix: %w", err)
	}
	tempPath := filepath.Join(dir, ".metadata.json.tmp-"+hex.EncodeToString(buf[:]))

	// fileio.WriteKeyFile creates the temp file exclusively, writes it, fsyncs
	// it and closes it. A temp file that already existed is not ours to remove.
	if err := fileio.WriteKeyFile(tempPath, data, 0600); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			_ = os.Remove(tempPath)
		}
		return fmt.Errorf("write metadata temp %q: %w", tempPath, err)
	}
	// Leave the temp file behind on a fault so the on-disk state mirrors a
	// crash that happened at this exact point.
	if err := seams.Fault("metadata-before-rename"); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(dir, layout.FileMetadata)); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename metadata temp to %q: %w", layout.FileMetadata, err)
	}
	if err := fileio.SyncDir(dir); err != nil {
		return fmt.Errorf("sync keys directory after metadata rename: %w", err)
	}
	return nil
}

// creationTime dates the key material. The private key's modification time is
// when it was written, which for a directory adopted from the pre-metadata
// layout beats stamping "now" onto keys that may be months old, and for a
// freshly generated one is already now. The fallback covers a private key that
// cannot be stat'ed.
func creationTime(dir string) string {
	if fi, err := os.Stat(filepath.Join(dir, layout.FilePrivateKey)); err == nil {
		return fi.ModTime().UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
