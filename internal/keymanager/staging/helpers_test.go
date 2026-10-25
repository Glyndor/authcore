package staging

import (
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

type silentLog struct{}

func (silentLog) Info(string, ...any) {}
func (silentLog) Warn(string, ...any) {}

func withFaultAt(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := seams.FaultAt
	if fn == nil {
		seams.FaultAt = func(string) error { return nil }
	} else {
		seams.FaultAt = fn
	}
	t.Cleanup(func() { seams.FaultAt = prev })
}

func withLinkFile(t *testing.T, fn func(string, string) error) {
	t.Helper()
	prev := seams.LinkFile
	seams.LinkFile = fn
	t.Cleanup(func() { seams.LinkFile = prev })
}
