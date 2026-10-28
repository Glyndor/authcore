//go:build !unix

package fileio

import (
	"fmt"
	"os"
)

// OpenRegular opens path for reading after checking that it is a regular file.
// Platforms without a non-blocking open cannot close the gap between the check
// and the open, but the type is checked again on the open descriptor.
//
// On Windows the open is repeated a bounded number of times while another
// handle holds the file for a moment (see retryOpen); the error of the last
// attempt is returned unchanged.
func OpenRegular(path string) (*os.File, error) {
	var f *os.File
	err := retryOpen(func() (oerr error) {
		f, oerr = openRegularOnce(path)
		return oerr
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// openRegularOnce is one attempt of OpenRegular.
func openRegularOnce(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is a %s, not a regular file", path, fi.Mode().Type())
	}
	// #nosec G304 -- path derived from trusted config.KeysDir and fixed filename, not user input
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err = f.Stat()
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
