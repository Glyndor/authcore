//go:build !windows

package fileio

import (
	"errors"
	"testing"
)

func TestRetryOpen_otherPlatformsRunOnce(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	if err := retryOpen(func() error { calls++; return boom }); !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("err=%v calls=%d, want boom and a single call", err, calls)
	}
}
