//go:build windows

package fileio

import (
	"errors"
	"syscall"
	"time"
)

// isTransientOpenError reports whether err carries a Windows error code that
// a concurrent initialiser finishing its publish can clear: while it links
// and then removes its staging directory, a reader that opens one of the
// staged files can be told the file is in use or that its delete is pending.
// Once the removal completes the same open answers "does not exist", which
// the callers already treat as "the owner finished".
func isTransientOpenError(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && isTransientCode(uintptr(errno))
}

// retryOpen runs op, repeating it a bounded number of times while it fails
// with a transient sharing condition.
func retryOpen(op func() error) error {
	return retryTransient(op, isTransientOpenError, time.Sleep)
}
