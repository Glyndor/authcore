package keyload

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/modecheck"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// The three key files are read one after another, so a process that replaces
// them while a start is reading (an operator rotating keys, a secret volume
// being refreshed) could hand the loader a signing key from one set and the
// refresh secret from another. When metadata.json holds a binding, the check
// after the read catches it; a directory written before the binding existed
// has nothing else to go on.
//
// The files are therefore read through descriptors, not through paths. Each
// file is opened and read in turn and its descriptor is kept open; once all
// three are read, every path is looked at again and must still lead to the
// very file its descriptor holds (os.SameFile: device and inode). If any of
// them does not, the bytes came from a version the path no longer names, so
// the read is thrown away and repeated. A secret volume that swaps one link to
// refresh all three files is caught because the paths now lead to files other
// than the ones held open. Comparing two looks at the paths instead (before and
// after) cannot do this: a volume that goes from one set to another and back
// during the read leaves both looks equal while the files were read from
// different versions. Only the open descriptors remember which version each
// file was read from.
//
// This detects a change during the read. It cannot tell that a directory has
// been left half replaced and has stayed that way: that state is on disk, and
// only the binding can recognise it. The paths are checked one after another,
// so a volume that flips back and forth between every single look could still
// get through; a refresh is one retarget of a link, not a flip per file.

// readAttempts bounds how often a read that overlapped a change is repeated.
const readAttempts = 3

// retryPause is how long to wait before reading again, so that a replacement
// in progress can finish. A variable so tests do not wait.
var retryPause = 20 * time.Millisecond

// Files loads the three key files from dir through the validators in
// keyload.go: size cap, PEM parse, pair consistency and secret length all
// apply. The read is repeated, a bounded number of times, when a file changes
// while the three are being read (see above); a set that never settles is
// refused. It warns, without ever refusing or changing a mode, when the
// private key or the refresh secret is readable by group or others.
//
// The loading path tolerates a read-only KeysDir: symlinks are followed and
// the size cap is honoured.
func Files(dir string, log layout.Logger) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	paths := []string{
		filepath.Join(dir, layout.FilePrivateKey),
		filepath.Join(dir, layout.FilePublicKey),
		filepath.Join(dir, layout.FileRefreshSecret),
	}

	var lastErr error
	for attempt := 0; attempt < readAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(retryPause)
		}
		data, settled, err := readStable(paths, attempt)
		if settled && err != nil {
			return nil, nil, nil, err
		}
		if !settled {
			lastErr = err
			continue
		}
		priv, pub, secret, err := decodeSet(paths, data)
		if err != nil {
			return nil, nil, nil, err
		}
		// Warn (never refuse, never chmod) when the private key or the
		// refresh secret is readable by group or others. The public key is
		// omitted by design: it is meant to be shared, so the same bit
		// pattern on it is not a finding.
		modecheck.WarnIfReadableByOthers(paths[0], log)
		modecheck.WarnIfReadableByOthers(paths[2], log)
		return priv, pub, secret, nil
	}
	// The files kept changing, or could not be inspected. A read that failed
	// for its own reason (a missing file) says why; a read that worked but
	// could not be vouched for does not.
	if lastErr != nil {
		return nil, nil, nil, lastErr
	}
	return nil, nil, nil, refusals.KeysChangedWhileReading(dir)
}

// readStable reads every path once through a descriptor kept open until all
// are read, then checks that each path still leads to its descriptor. settled
// reports whether the outcome can be trusted: false means a path moved (or a
// file vanished) during the read and the caller should repeat it, with err
// carrying the I/O error behind it when there was one. When settled, err is a
// failure of the read itself, which repeating would not change.
func readStable(paths []string, attempt int) (data [][]byte, settled bool, err error) {
	files := make([]*os.File, 0, len(paths))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for i, p := range paths {
		f, err := fileio.OpenRegular(p)
		if err != nil {
			// A vanished file may be a replacement in progress.
			return nil, !errors.Is(err, fs.ErrNotExist) && leadToSame(paths, files), readErr(i, p, err)
		}
		files = append(files, f)
		b, err := fileio.ReadCappedFile(f, p)
		if err != nil {
			return nil, leadToSame(paths, files), readErr(i, p, err)
		}
		data = append(data, b)
		if seams.AfterKeyRead != nil {
			seams.AfterKeyRead(attempt, i)
		}
	}
	return data, leadToSame(paths, files), nil
}

// leadToSame reports whether each of the first len(files) paths still resolves
// to the file its descriptor holds. A path that cannot be inspected counts as
// moved.
func leadToSame(paths []string, files []*os.File) bool {
	for i, f := range files {
		now, err := os.Stat(paths[i])
		if err != nil {
			return false
		}
		held, err := f.Stat()
		if err != nil || !os.SameFile(now, held) {
			return false
		}
	}
	return true
}

// decodeSet validates the bytes of the three files read by readStable.
func decodeSet(paths []string, data [][]byte) (ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	priv, pub, err := decodeEd25519(data[0], data[1], paths[0], paths[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ed25519 key pair: %w", err)
	}
	secret, err := decodeRefreshSecret(data[2], paths[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("refresh secret: %w", err)
	}
	return priv, pub, secret, nil
}

// readErr words a failure to open or read file number i the way the path-based
// loaders do.
func readErr(i int, path string, err error) error {
	switch i {
	case 0:
		return fmt.Errorf("ed25519 key pair: load private key: %w", err)
	case 1:
		return fmt.Errorf("ed25519 key pair: load public key: %w", err)
	}
	return fmt.Errorf("refresh secret: read refresh secret from %q: %w", path, err)
}
