package seams_test

import (
	"errors"
	"runtime"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func TestGOOS_defaultsToRuntime(t *testing.T) {
	if seams.GOOS != runtime.GOOS {
		t.Fatalf("GOOS = %q, want %q", seams.GOOS, runtime.GOOS)
	}
}

func TestFault_defaultsToNoFault(t *testing.T) {
	if err := seams.Fault("staged"); err != nil {
		t.Fatalf("default Fault returned %v, want nil", err)
	}
}

func TestFault_followsTheHook(t *testing.T) {
	boom := errors.New("boom")
	prev := seams.FaultAt
	t.Cleanup(func() { seams.FaultAt = prev })
	seams.FaultAt = func(point string) error {
		if point == "staged" {
			return boom
		}
		return nil
	}
	if err := seams.Fault("staged"); !errors.Is(err, boom) {
		t.Fatalf("Fault(staged) = %v, want boom", err)
	}
	if err := seams.Fault("published-private"); err != nil {
		t.Fatalf("Fault(published-private) = %v, want nil", err)
	}
}
