// Package stagingtest is the test-side support for the staging packages: a
// silent logger, the two filesystem seams, and the small fixtures the
// createset, linkkeys, preflight and publish tests share. Only _test.go files
// import it.
package stagingtest

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// SilentLog is a layout.Logger that drops everything.
type SilentLog struct{}

// Info discards the message.
func (SilentLog) Info(string, ...any) {}

// Warn discards the message.
func (SilentLog) Warn(string, ...any) {}

// WithFaultAt replaces the publish-transaction fault seam for the duration of
// the test. A nil fn installs a seam that never faults.
func WithFaultAt(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := seams.FaultAt
	if fn == nil {
		seams.FaultAt = func(string) error { return nil }
	} else {
		seams.FaultAt = fn
	}
	t.Cleanup(func() { seams.FaultAt = prev })
}

// WithLinkFile replaces the hard-link seam for the duration of the test.
func WithLinkFile(t *testing.T, fn func(string, string) error) {
	t.Helper()
	prev := seams.LinkFile
	seams.LinkFile = fn
	t.Cleanup(func() { seams.LinkFile = prev })
}

// PosixOnly skips the test where hard links and Unix modes are unavailable.
func PosixOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hard links and Unix modes require POSIX semantics")
	}
}

// StagingDirs lists the staging directories currently inside dir.
func StagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}
