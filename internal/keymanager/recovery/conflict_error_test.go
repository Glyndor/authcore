package recovery_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// A conflict that cannot be examined is not "no conflict".
func TestRefuseConflict_PassesOnAnExaminationFailure(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	staging := recoverytest.StagingFrom(t, dir, "copy", dir)
	big := make([]byte, layout.MaxKeyFileSize+1)
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), big, 0o600); err != nil {
		t.Fatal(err)
	}

	err := recovery.RefuseConflict(dir)
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("RefuseConflict = %v, want the size error", err)
	}
}

// A key name that cannot be classified stops the recovery with that error; it
// is not mistaken for "no staging directory matches".
func TestTryRecover_ReportsAnUninspectableKeyName(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := t.TempDir()
	loop := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.Symlink(layout.FilePrivateKey, loop); err != nil {
		t.Fatal(err)
	}

	err := recovery.TryRecover(dir, recoverytest.SilentLog{})
	if err == nil || errors.Is(err, recovery.ErrNoMatchingStaging) {
		t.Fatalf("TryRecover = %v, want the inspection error", err)
	}
}

// A directory that cannot be listed cannot be searched for a staging set; that
// is an error of its own, not a verdict that nothing matches.
func TestTryRecover_ReportsAnUnlistableDirectory(t *testing.T) {
	recoverytest.PosixOnly(t)
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := recovery.TryRecover(dir, recoverytest.SilentLog{})
	if err == nil || errors.Is(err, recovery.ErrNoMatchingStaging) {
		t.Fatalf("TryRecover = %v, want the listing error", err)
	}
}
