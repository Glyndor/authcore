package fileio

import (
	"errors"
	"syscall"
	"testing"
)

// failingFile fails the step it is told to and records whether it was closed.
type failingFile struct {
	writeErr, syncErr, closeErr error
	closed                      bool
}

func (f *failingFile) Write(p []byte) (int, error) { return len(p), f.writeErr }
func (f *failingFile) Sync() error                 { return f.syncErr }
func (f *failingFile) Close() error                { f.closed = true; return f.closeErr }

func TestWriteSyncClose_everyStepFailureIsReturnedAndTheFileIsClosed(t *testing.T) {
	boom := errors.New("boom")
	for name, f := range map[string]*failingFile{
		"write": {writeErr: boom},
		"sync":  {syncErr: boom},
		"close": {closeErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			if err := writeSyncClose(f, []byte("x")); !errors.Is(err, boom) {
				t.Fatalf("writeSyncClose = %v, want boom", err)
			}
			if !f.closed {
				t.Fatal("the file was left open")
			}
		})
	}
}

func TestTolerateUnsupportedSync(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		in   error
		want error
	}{
		{"no error", nil, nil},
		{"unsupported", errors.ErrUnsupported, nil},
		{"einval", syscall.EINVAL, nil},
		{"anything else", boom, boom},
	} {
		if got := tolerateUnsupportedSync(tc.in); !errors.Is(got, tc.want) && got != tc.want {
			t.Errorf("%s: tolerateUnsupportedSync(%v) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}
