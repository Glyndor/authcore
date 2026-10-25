package keyload

import (
	"os"
	"time"
)

// The three key files are read one after another, so a process that replaces
// them while a start is reading (an operator rotating keys, a secret volume
// being refreshed) could hand the loader a signing key from one set and the
// refresh secret from another. When metadata.json holds a binding, the check
// after the read catches it; a directory written before the binding existed
// has nothing else to go on.
//
// The read is therefore bracketed by two looks at the identity of the files:
// if any of them changed while the three were being read, the read is thrown
// away and repeated. Identity is what os.Stat reports after following links:
// device, inode, size and modification time. A secret volume that swaps one
// link to refresh all three files is caught because the inode behind the
// paths changes.
//
// This detects a change during the read. It cannot tell that a directory has
// been left half replaced and has stayed that way: that state is on disk, and
// only the binding can recognise it.

// readAttempts bounds how often a read that overlapped a change is repeated.
const readAttempts = 3

// retryPause is how long to wait before reading again, so that a replacement
// in progress can finish. A variable so tests do not wait.
var retryPause = 20 * time.Millisecond

// afterRead is called once the three files have been read and before the
// second look at them. It exists for tests; production leaves it nil.
var afterRead func(attempt int)

// fileID is what identifies one version of a file.
type fileID struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

// snapshot returns the identity of every path, in order.
func snapshot(paths []string) ([]fileID, error) {
	ids := make([]fileID, len(paths))
	for i, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		ids[i] = fileID{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
		ids[i].dev, ids[i].ino = deviceAndInode(fi)
	}
	return ids, nil
}

// same reports whether two snapshots describe the same files.
func same(a, b []fileID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
