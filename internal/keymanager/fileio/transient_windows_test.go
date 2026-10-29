//go:build windows

package fileio

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestIsTransientOpenError_windows(t *testing.T) {
	wrap := func(e error) error { return &fs.PathError{Op: "open", Path: "x", Err: e} }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"sharing violation", wrap(syscall.Errno(32)), true},
		{"access denied wrapped", fmt.Errorf("ctx: %w", wrap(syscall.Errno(5))), true},
		{"not found", wrap(syscall.Errno(2)), false},
		{"plain error", os.ErrInvalid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientOpenError(tc.err); got != tc.want {
				t.Fatalf("isTransientOpenError = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRetryOpen_windowsRetriesTransientThenSucceeds(t *testing.T) {
	calls := 0
	err := retryOpen(func() error {
		calls++
		if calls < 3 {
			return &fs.PathError{Op: "open", Path: "x", Err: syscall.Errno(32)}
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want nil and 3", err, calls)
	}
}
