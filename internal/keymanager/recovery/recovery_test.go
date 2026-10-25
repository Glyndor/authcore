package recovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// RecoverPartial's "set completes between checks" branch. The first
// TryRecover inspects a partial set with no matching staging, returns
// ErrNoMatchingStaging; recoverPartialBetweenChecksHook completes the set
// before the second inspection; RecoverPartial then sees fsguard.SetComplete and
// returns nil.
//
// The hook is the minimal unexported seam needed to drive the production
// path deterministically: a real concurrent helper would race either before
// or after the first inspect and the test could not pin which branch fired.
func TestRecoverPartialLoadsWhenSetCompletesBetweenChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}

	copyFile(t, filepath.Join(owner, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	copyFile(t, filepath.Join(owner, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))

	prev := recoverPartialBetweenChecksHook
	t.Cleanup(func() { recoverPartialBetweenChecksHook = prev })
	recoverPartialBetweenChecksHook = func() {
		copyFile(t, filepath.Join(owner, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))
	}

	if err := RecoverPartial(dir, silentLog{}); err != nil {
		t.Fatalf("RecoverPartial refused a set completed between checks: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
}

// TryRecover's inspect-error branch: a hostile entry inside a partial set
// must surface the inspect error before any recovery is attempted. New
// refuses a hostile set at the entry inspectKeySet, so this test drives
// TryRecover directly.
func TestTryRecover_inspectErrorIsReturned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}
	dir := t.TempDir()
	if _, err := seedKeys(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, layout.FilePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	err := TryRecover(dir, silentLog{})
	if err == nil {
		t.Fatal("TryRecover succeeded despite a hostile entry")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error must come from inspect, got: %v", err)
	}
}

// RecoverPartial's "second inspect surfaces an error after the hook" branch.
// The first TryRecover sees a partial set with no matching staging and
// returns ErrNoMatchingStaging. The hook then plants a hostile entry (a
// symlink loop at the missing slot) so the second inspect fails. New must
// surface the inspect error rather than refuseInconsistent.
func TestRecoverPartial_inspectErrorAfterHookIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := seedKeys(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(dir, name))
	}

	prev := recoverPartialBetweenChecksHook
	t.Cleanup(func() { recoverPartialBetweenChecksHook = prev })
	recoverPartialBetweenChecksHook = func() {
		loop := filepath.Join(dir, layout.FileRefreshSecret)
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
	}

	err := RecoverPartial(dir, silentLog{})
	if err == nil {
		t.Fatal("RecoverPartial succeeded despite a hostile entry after the hook")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error must come from inspect, got: %v", err)
	}
}

func TestRecoverPartial_rejectsSymlinkLoopInPartialSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}

	dir := t.TempDir()
	if _, err := seedKeys(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, layout.FilePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	err := RecoverPartial(dir, silentLog{})
	if err == nil {
		t.Fatal("RecoverPartial succeeded with a partial set containing an inspect error")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error should come from inspect, got: %v", err)
	}
}
