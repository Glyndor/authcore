//go:build unix

package fileio

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadCapped_aPipeIsRefusedWithoutWaitingForAWriter(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadCapped(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("ReadCapped(pipe) = %v, want the regular-file refusal", err)
		}
	case <-time.After(2 * time.Second):
		if f, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("ReadCapped waited for a writer")
	}
}

func TestReadCapped_followsALinkToARegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCapped(link)
	if err != nil || string(got) != "abc" {
		t.Fatalf("ReadCapped(link) = %q, %v", got, err)
	}
}
