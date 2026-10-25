//go:build unix

package bootstrap_test

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A FIFO at metadata.json used to block New and Load in open forever, since
// the marker was read before any regular-file check. Both must refuse it.
func TestMetadataFIFOIsRefusedNotOpened(t *testing.T) {
	for name, open := range map[string]func(string, layout.Logger) (*bootstraptest.KeyManager, error){"New": bootstraptest.New, "Load": bootstraptest.Load} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if name == "Load" {
				if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
					t.Fatalf("provision: %v", err)
				}
				if err := syscall.Unlink(filepath.Join(dir, layout.FileMetadata)); err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(filepath.Join(dir, layout.FileMetadata), 0o600); err != nil {
				t.Fatalf("mkfifo: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := open(dir, bootstraptest.SilentLog{})
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
