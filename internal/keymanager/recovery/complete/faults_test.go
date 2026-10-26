package complete

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// partialWithStaging returns a key directory that holds only the files in keep,
// next to a staging directory with the whole set.
func partialWithStaging(t *testing.T, keep ...string) (dir, staging string) {
	t.Helper()
	recoverytest.PosixOnly(t)
	base := t.TempDir()
	dir = filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	src := recoverytest.MustSeed(t, filepath.Join(base, "owner"))
	staging = recoverytest.StagingFrom(t, dir, "aaaa", src)
	for _, name := range keep {
		recoverytest.CopyFile(t, filepath.Join(src, name), filepath.Join(dir, name))
	}
	return dir, staging
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Pass one judges every published file before pass two links anything: a file
// that cannot be read stops the recovery with nothing linked.
func TestFromStaging_AnUnreadablePublishedFileLinksNothing(t *testing.T) {
	dir, staging := partialWithStaging(t, layout.FilePrivateKey)
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), make([]byte, layout.MaxKeyFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}

	err := FromStaging(dir, staging)
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("FromStaging = %v, want the size error", err)
	}
	if exists(filepath.Join(dir, layout.FilePublicKey)) {
		t.Error("the public key was linked although pass one had failed")
	}
}

// The staged file vanishing while a concurrent helper's link is compared means
// the owner finished: keep waiting, do not invent a success.
func TestFromStaging_ReportsAStagedFileThatCannotBeComparedAfterAConcurrentLink(t *testing.T) {
	dir, staging := partialWithStaging(t, layout.FilePrivateKey)
	recoverytest.WithLinkFile(t, func(src, dst string) error {
		if filepath.Base(dst) != layout.FilePublicKey {
			return os.Link(src, dst)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(src, make([]byte, layout.MaxKeyFileSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		return &os.LinkError{Op: "link", Old: src, New: dst, Err: fs.ErrExist}
	})

	err := FromStaging(dir, staging)
	if err == nil || !strings.Contains(err.Error(), "compare") || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("FromStaging = %v, want the comparison error", err)
	}
}

func TestFromStaging_ReportsAFailedDirectorySyncAfterLinking(t *testing.T) {
	dir, staging := partialWithStaging(t, layout.FilePrivateKey, layout.FilePublicKey)
	recoverytest.WithLinkFile(t, func(src, dst string) error {
		if err := os.Link(src, dst); err != nil {
			return err
		}
		// The directory goes away right after its last file is linked.
		return os.Rename(dir, dir+".gone")
	})

	err := FromStaging(dir, staging)
	if err == nil || !strings.Contains(err.Error(), "sync keys directory after recovery") {
		t.Fatalf("FromStaging = %v, want the failed directory sync", err)
	}
}

// With the staged set vouched for, a published file whose staged copy has
// disappeared is the owner finishing, not a set to link from.
func TestFromStaging_PassOneStagedFileGoneMeansKeepWaiting(t *testing.T) {
	dir, staging := partialWithStaging(t, layout.FilePrivateKey)
	if err := os.Remove(filepath.Join(staging, layout.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}
	prev := checkStaged
	checkStaged = func(string) error { return nil }
	t.Cleanup(func() { checkStaged = prev })

	if err := FromStaging(dir, staging); !errors.Is(err, match.ErrNoMatchingStaging) {
		t.Fatalf("FromStaging = %v, want match.ErrNoMatchingStaging", err)
	}
}
