//go:build unix

package fileio

import (
	"fmt"
	"os"
	"syscall"
)

// openRegular opens path for reading without ever waiting on it. A plain open
// of a named pipe blocks until a writer appears, so a key file swapped for a
// pipe between a caller's Stat and this open would hang the start. With
// O_NONBLOCK the open returns at once, and the type is then checked on the open
// descriptor, which cannot change underneath the check. The flag has no effect
// on the reads of a regular file.
func openRegular(path string) (*os.File, error) {
	// #nosec G304 -- path derived from trusted config.KeysDir and fixed filename, not user input
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%q is a %s, not a regular file", path, fi.Mode().Type())
	}
	return f, nil
}
