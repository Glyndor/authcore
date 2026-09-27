//go:build unix

package keymanager

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO at metadata.json used to block New and Load in open forever, since
// the marker was read before any regular-file check. Both must refuse it.
func TestMetadataFIFOIsRefusedNotOpened(t *testing.T) {
	for name, open := range map[string]func(string, logger) (*KeyManager, error){"New": New, "Load": Load} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if name == "Load" {
				if _, err := New(dir, silentLog{}); err != nil {
					t.Fatalf("provision: %v", err)
				}
				if err := syscall.Unlink(filepath.Join(dir, fileMetadata)); err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(filepath.Join(dir, fileMetadata), 0o600); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := open(dir, silentLog{})
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("%s = %v, want the not-a-regular-file refusal", name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s is still blocked on the FIFO after 10 s", name)
			}
		})
	}
}
