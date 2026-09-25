package keymanager

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// currentFormat is the version of the on-disk layout this build writes and
// understands. Bump it only when the meaning of an existing file changes —
// adding a new file that older versions simply ignore does not need a bump.
const currentFormat = 1

// fileMetadata records which layout wrote the key directory.
//
// The library allows breaking changes and ships them forward, and it persists
// key material on disk, so a release that changes the on-disk format has to
// migrate what is already there rather than regenerate it: regenerating
// invalidates every refresh-token and API-key hash the consumer has stored,
// which logs out all of their users. That migration is only possible if the
// loader can tell what wrote the directory, which is what this file is for.
const fileMetadata = "metadata.json"

// metadata is the content of fileMetadata. It holds no secret — KeyID is
// derived from the public key and already travels in every JWT header — but it
// is written 0600 anyway, since nothing outside authcore reads it.
type metadata struct {
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
}

// errFormatFromFuture reports a directory written by a newer authcore.
var errFormatFromFuture = errors.New("key directory was written by a newer version of authcore")

// readMetadata loads the descriptor from dir.
//
// A missing file is not an error: it means the pre-metadata layout, and the
// caller adopts it. Anything else — unreadable, malformed, or a format this
// build does not understand — is fatal, because the whole point of the marker
// is to stop a loader from guessing at key material it may not understand.
func readMetadata(dir string) (*metadata, error) {
	path := filepath.Join(dir, fileMetadata)

	// The key files are refused unless they are regular files; the marker
	// was opened without that check, so a FIFO here blocked New and Load in
	// open forever (measured 2026-09-25).
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is a %s, not a regular file; authcore refuses to read it as the key layout marker",
			path, fi.Mode().Type())
	}

	data, err := readCapped(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // pre-metadata layout
		}
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	var m metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf(
			"parse %q: %w; the file describes the key layout and holds no key material, "+
				"so deleting it is safe and makes authcore re-adopt the existing keys",
			path, err,
		)
	}

	if m.Format > currentFormat {
		return nil, fmt.Errorf(
			"%w: %q reports format %d, this build understands %d; upgrade authcore rather than downgrading the directory",
			errFormatFromFuture, path, m.Format, currentFormat,
		)
	}
	if m.Format < 1 {
		return nil, fmt.Errorf("%q reports an invalid format %d", path, m.Format)
	}

	return &m, nil
}

// syncMetadata brings the descriptor in line with the keys that were just
// loaded or generated: it writes one for a directory that has none (adopting
// the pre-metadata layout in place, without touching the keys), and refreshes
// the recorded key id when the signing key has been rotated underneath.
//
// A genuine write failure is reported to the log and not returned: the
// descriptor is bookkeeping and a read-only KeysDir (a mounted secret) is a
// supported deployment, so a metadata write that fails must not stop a
// service from starting. A faultAt return is a test-only signal and is
// returned verbatim so the publish transaction aborts as a crash would.
func syncMetadata(dir string, existing *metadata, keyID string, log logger) error {
	switch {
	case existing == nil:
		m := metadata{
			Format:  currentFormat,
			Created: creationTime(dir),
			KeyID:   keyID,
		}
		if err := writeMetadata(dir, m); err != nil {
			log.Warn("authcore/keymanager: could not write %s in %q (continuing): %v", fileMetadata, dir, err)
			return nil
		}
		if err := faultAt("metadata-written"); err != nil {
			return err
		}
		log.Info("authcore/keymanager: recorded on-disk format %d for %s", currentFormat, dir)

	case existing.KeyID != keyID:
		// The signing key changed since the descriptor was written — a manual
		// rotation, or keys restored from elsewhere. Follow the keys.
		m := *existing
		m.KeyID = keyID
		if err := writeMetadata(dir, m); err != nil {
			log.Warn("authcore/keymanager: could not update %s in %q (continuing): %v", fileMetadata, dir, err)
			return nil
		}
		if err := faultAt("metadata-written"); err != nil {
			return err
		}
		log.Info("authcore/keymanager: signing key changed, %s now records key id %s", fileMetadata, keyID)
	}
	return nil
}

// writeMetadata serialises m into dir atomically.
//
// The file is written to a random-named temp sibling, fsynced, then renamed
// onto metadata.json. The rename is the commit; on a crash mid-write, the
// previous metadata.json (or its absence) is preserved and the temp file is
// left behind for the operator to inspect or remove. A second crash between
// the rename and the directory sync could still see the new metadata as
// unpublished, but the previous metadata.json is what readMetadata would have
// returned; the worst case is a one-startup delay, not a torn file.
//
// syncMetadata wraps this so failures stay warnings and never block startup;
// writeMetadata itself returns errors because the metadata tests pin them.
func writeMetadata(dir string, m metadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", fileMetadata, err)
	}
	data = append(data, '\n')

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Errorf("generate metadata temp suffix: %w", err)
	}
	tempPath := filepath.Join(dir, ".metadata.json.tmp-"+hex.EncodeToString(buf[:]))

	// #nosec G304 -- tempPath is KeysDir joined with a name generated here from crypto/rand, never request input
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create metadata temp %q: %w", tempPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("write metadata temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("sync metadata temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close metadata temp: %w", err)
	}
	// Leave the temp file behind on a fault so the on-disk state mirrors a
	// crash that happened at this exact point.
	if err := faultAt("metadata-before-rename"); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(dir, fileMetadata)); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename metadata temp to %q: %w", fileMetadata, err)
	}
	if err := syncDir(dir); err != nil {
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
	if fi, err := os.Stat(filepath.Join(dir, filePrivateKey)); err == nil {
		return fi.ModTime().UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
