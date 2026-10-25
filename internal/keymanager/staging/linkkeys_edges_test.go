package staging

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// stagedSet writes the three files of a staging directory with distinct bytes.
func stagedSet(t *testing.T, dir, name string) string {
	t.Helper()
	staging := filepath.Join(dir, layout.StagingPrefix+name)
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, f), []byte("staged-"+f), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return staging
}

// The public slot is taken by an identical file another process linked (a
// different inode, so the link did not land here), and then the staged source
// disappears before it is compared: the owner finished and removed its staging
// directory. The caller is asked to wait for the set rather than to fail.
func TestLinkKeys_stagedSourceVanishesAfterAnIdenticalConcurrentLink(t *testing.T) {
	posixOnly(t)
	dir := t.TempDir()
	staging := stagedSet(t, dir, "aaaa")
	pub := filepath.Join(dir, layout.FilePublicKey)
	if err := os.WriteFile(pub, []byte("staged-"+layout.FilePublicKey), 0644); err != nil {
		t.Fatal(err)
	}

	var calls int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return os.Link(oldpath, newpath)
		}
		// The owner removes the staged public key just as we lose the race for it.
		_ = os.Remove(oldpath)
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if !errors.Is(err, ErrWaitAndLoad) {
		t.Fatalf("linkKeys = %v, want ErrWaitAndLoad", err)
	}
	if _, serr := os.Stat(staging); !os.IsNotExist(serr) {
		t.Errorf("the vanished owner's staging directory should have been removed: %v", serr)
	}
}

func TestLinkKeys_stagedSourceTooLargeIsSurfaced(t *testing.T) {
	posixOnly(t)
	dir := t.TempDir()
	staging := stagedSet(t, dir, "bbbb")
	pub := filepath.Join(dir, layout.FilePublicKey)
	if err := os.WriteFile(pub, []byte("small"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey), make([]byte, layout.MaxKeyFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}

	var calls int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return os.Link(oldpath, newpath)
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil || !strings.Contains(err.Error(), "read staged") {
		t.Fatalf("linkKeys = %v, want the read-staged failure", err)
	}
}

// A directory that cannot be synced after the last link is an error: the
// publish is not durable. Needs a directory the process can write but not open
// for reading, which root ignores.
func TestLinkKeys_syncFailureAfterPublishIsReturned(t *testing.T) {
	posixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	dir := t.TempDir()
	staging := stagedSet(t, dir, "cccc")
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	var calls int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if err := os.Link(oldpath, newpath); err != nil {
			return err
		}
		if atomic.AddInt32(&calls, 1) == 3 {
			// Write and search stay; read goes, so Open for fsync fails.
			return os.Chmod(dir, 0300)
		}
		return nil
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil || !strings.Contains(err.Error(), "sync keys directory after publish") {
		t.Fatalf("linkKeys = %v, want the sync-after-publish failure", err)
	}
}
