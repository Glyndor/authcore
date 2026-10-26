package match_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/match"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

func oversize(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, layout.MaxKeyFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A directory that cannot be listed is an error, not "no staging directory
// matches": the caller would otherwise keep waiting for something that cannot
// appear, or refuse with the wrong advice.
func TestFindStaging_ReportsAListingFailure(t *testing.T) {
	_, err := match.FindStaging(filepath.Join(t.TempDir(), "absent"))
	if err == nil || errors.Is(err, match.ErrNoMatchingStaging) {
		t.Fatalf("FindStaging on a missing directory = %v, want the listing error", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

func TestFindStaging_ReportsAnUnreadableStagedPrivateKey(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	staging := recoverytest.StagingFrom(t, dir, "big", dir)
	oversize(t, filepath.Join(staging, layout.FilePrivateKey))

	_, err := match.FindStaging(dir)
	if err == nil || errors.Is(err, match.ErrNoMatchingStaging) || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("FindStaging = %v, want the size error of the staged private key", err)
	}
}

func TestConflict_ReportsAnUnreadableStagedPrivateKey(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	staging := recoverytest.StagingFrom(t, dir, "big", dir)
	oversize(t, filepath.Join(staging, layout.FilePrivateKey))

	name, err := match.Conflict(dir)
	if err == nil || name != "" || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("Conflict = %q, %v, want the size error of the staged private key", name, err)
	}
}

func TestConflict_ReportsAnUnreadablePublishedFile(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	recoverytest.StagingFrom(t, dir, "copy", dir)
	oversize(t, filepath.Join(dir, layout.FilePublicKey))

	name, err := match.Conflict(dir)
	if err == nil || name != "" || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("Conflict = %q, %v, want the size error of the published public key", name, err)
	}
}

func TestConflict_ReportsAnUnreadableStagedFile(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	staging := recoverytest.StagingFrom(t, dir, "copy", dir)
	oversize(t, filepath.Join(staging, layout.FilePublicKey))

	name, err := match.Conflict(dir)
	if err == nil || name != "" || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("Conflict = %q, %v, want the size error of the staged public key", name, err)
	}
}
