//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
)

// Callers classify an entry with Stat before reading it, so a named pipe is
// refused up front. The read itself must also hold when the entry changes type
// between that check and the open: it must return, not wait for a writer.
func TestHostile_ReadCapped_returnsForAnEntryThatBecameAPipe(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "swapped")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := fileio.ReadCapped(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("ReadCapped returned no error for a pipe")
		}
	case <-time.After(2 * time.Second):
		// Release the blocked goroutine so the test binary can exit.
		if f, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
		}
		t.Error("ReadCapped did not return for a pipe within 2s")
	}
}
