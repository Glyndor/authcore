package fileio

import "time"

// Windows error codes that mean "another handle holds this file right now":
// ERROR_ACCESS_DENIED (a file whose delete is pending answers an open with
// it), ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION. They are plain
// numbers so the classification below runs, and is tested, on every platform.
const (
	winErrAccessDenied     = 5
	winErrSharingViolation = 32
	winErrLockViolation    = 33
)

// transientAttempts bounds how often a transient open is tried. The wait
// between attempts grows from transientFirstWait, doubling each time, so the
// whole budget is 2+4+...+512 ms, about a second. Thirty milliseconds (five
// attempts) was shorter than the time a loaded Windows runner kept a file in
// delete-pending while its owner cleaned a staging directory, and the reader
// then failed instead of seeing the file gone.
const (
	transientAttempts  = 10
	transientFirstWait = 2 * time.Millisecond
)

// isTransientCode reports whether a Windows error code describes a condition
// another handle on the same file can clear by itself: the file is held open
// or is being deleted. It is a pure function of the code.
func isTransientCode(code uintptr) bool {
	switch code {
	case winErrAccessDenied, winErrSharingViolation, winErrLockViolation:
		return true
	}
	return false
}

// retryTransient runs op up to transientAttempts times. It repeats only while
// transient reports the returned error as transient, and waits between
// attempts through sleep. The error of the last attempt is returned unchanged,
// so a condition that does not clear is reported as it was, and a success or a
// non-transient error ends the loop at once.
func retryTransient(op func() error, transient func(error) bool, sleep func(time.Duration)) error {
	wait := transientFirstWait
	var err error
	for attempt := 1; attempt <= transientAttempts; attempt++ {
		err = op()
		if err == nil || !transient(err) || attempt == transientAttempts {
			return err
		}
		sleep(wait)
		wait *= 2
	}
	return err
}
