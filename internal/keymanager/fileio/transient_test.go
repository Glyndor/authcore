package fileio

import (
	"errors"
	"io/fs"
	"testing"
	"time"
)

func TestIsTransientCode_table(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uintptr
		want bool
	}{
		{"access denied", 5, true},
		{"sharing violation", 32, true},
		{"lock violation", 33, true},
		{"file not found", 2, false},
		{"path not found", 3, false},
		{"already exists", 80, false},
		{"zero", 0, false},
		{"neighbour below", 4, false},
		{"neighbour above", 34, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientCode(tc.code); got != tc.want {
				t.Fatalf("isTransientCode(%d) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

func TestRetryTransient_succeedsAfterTransientFailures(t *testing.T) {
	busy := errors.New("busy")
	calls := 0
	var waits []time.Duration
	err := retryTransient(func() error {
		calls++
		if calls < 3 {
			return busy
		}
		return nil
	}, func(e error) bool { return e == busy }, func(d time.Duration) { waits = append(waits, d) })
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want nil and 3", err, calls)
	}
	if len(waits) != 2 || waits[0] != transientFirstWait || waits[1] != 2*transientFirstWait {
		t.Fatalf("waits = %v, want two growing waits starting at %v", waits, transientFirstWait)
	}
}

func TestRetryTransient_boundedAndReturnsLastError(t *testing.T) {
	busy := errors.New("busy")
	calls, sleeps := 0, 0
	err := retryTransient(func() error { calls++; return busy },
		func(error) bool { return true }, func(time.Duration) { sleeps++ })
	if !errors.Is(err, busy) {
		t.Fatalf("err = %v, want the transient error unchanged", err)
	}
	if calls != transientAttempts || sleeps != transientAttempts-1 {
		t.Fatalf("calls=%d sleeps=%d, want %d and %d", calls, sleeps, transientAttempts, transientAttempts-1)
	}
}

// A file whose delete is pending answers an open with access denied until the
// last handle closes, then with not-exist. The reader must outlast a pending
// delete of 64 ms and report the file gone, not the transient error.
func TestRetryTransient_outlastsAPendingDeleteAndReportsTheFileGone(t *testing.T) {
	const pending = 64 * time.Millisecond
	busy := errors.New("access denied")
	var elapsed time.Duration
	err := retryTransient(func() error {
		if elapsed < pending {
			return busy
		}
		return fs.ErrNotExist
	}, func(e error) bool { return e == busy }, func(d time.Duration) { elapsed += d })
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v after %v of waiting, want not-exist once the delete completed", err, elapsed)
	}
}

func TestRetryTransient_nonTransientAndSuccessStopAtOnce(t *testing.T) {
	hard := errors.New("hard")
	calls := 0
	err := retryTransient(func() error { calls++; return hard },
		func(error) bool { return false }, func(time.Duration) { t.Fatal("slept on a non-transient error") })
	if !errors.Is(err, hard) || calls != 1 {
		t.Fatalf("err=%v calls=%d, want hard and 1", err, calls)
	}
	calls = 0
	if err := retryTransient(func() error { calls++; return nil },
		func(error) bool { return true }, func(time.Duration) { t.Fatal("slept after success") }); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d, want nil and 1", err, calls)
	}
}
