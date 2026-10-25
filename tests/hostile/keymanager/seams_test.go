//go:build unix

package hostile

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// errCrash is what the seams return to stand for a process that died there.
var errCrash = errors.New("simulated crash")

// setFault installs fn as the crash seam for the rest of the test. The hook is
// process-global, which is why no test in this package runs in parallel.
func setFault(t testing.TB, fn func(point string) error) {
	t.Helper()
	prev := seams.FaultAt
	seams.FaultAt = fn
	t.Cleanup(func() { seams.FaultAt = prev })
}

// crashAt makes the publish transaction abort at point, once, without cleanup.
func crashAt(t testing.TB, point string) {
	t.Helper()
	done := false
	setFault(t, func(p string) error {
		if p == point && !done {
			done = true
			return errCrash
		}
		return nil
	})
}

// setLink installs fn as the hard-link call for the rest of the test.
func setLink(t testing.TB, fn func(oldname, newname string) error) {
	t.Helper()
	prev := seams.LinkFile
	seams.LinkFile = fn
	t.Cleanup(func() { seams.LinkFile = prev })
}
