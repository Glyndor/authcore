package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

var (
	posixOnly   = recoverytest.PosixOnly
	mustSeed    = recoverytest.MustSeed
	stagingFrom = recoverytest.StagingFrom
	complete    = recoverytest.Complete
)

// A publisher that died after linking the private key leaves a partial set and
// a staging directory holding all three files. Recovery links the rest from it.
func TestRecoverPartial_completesTheSetFromTheMatchingStaging(t *testing.T) {
	posixOnly(t)
	base := t.TempDir()
	owner := mustSeed(t, filepath.Join(base, "owner"))
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stagingFrom(t, dir, "0123456789abcdef", owner)
	copyFile(t, filepath.Join(owner, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	if err := RecoverPartial(dir, silentLog{}); err != nil {
		t.Fatalf("RecoverPartial: %v", err)
	}
	if !complete(t, dir) {
		t.Fatal("the set is still partial after recovery")
	}
	for _, f := range layout.KeyFileNames() {
		want, _ := os.ReadFile(filepath.Join(owner, f)) // #nosec G304 -- test fixture
		got, _ := os.ReadFile(filepath.Join(dir, f))    // #nosec G304 -- test fixture
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from the staged copy", f)
		}
	}
	if len(listStagingDirs(t, dir)) != 1 {
		t.Error("recovery must leave the staging directory in place: its owner may still be running")
	}
}

// Recovery picks the staging directory whose private key matches the
// published one, whichever sorts first. With the comparison always true the
// first directory in name order was used, and an unrelated leftover that
// sorted first turned a recoverable state into a refusal.
func TestRecoverPartial_picksTheStagingThatMatchesEvenWhenItSortsLast(t *testing.T) {
	posixOnly(t)
	base := t.TempDir()
	unrelated := mustSeed(t, filepath.Join(base, "unrelated"))
	matching := mustSeed(t, filepath.Join(base, "matching"))
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stagingFrom(t, dir, "0000000000000000", unrelated)
	stagingFrom(t, dir, "ffffffffffffffff", matching)
	copyFile(t, filepath.Join(matching, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	if err := RecoverPartial(dir, silentLog{}); err != nil {
		t.Fatalf("RecoverPartial: %v, want it recovered from the matching staging", err)
	}
	want, _ := os.ReadFile(filepath.Join(matching, layout.FilePublicKey)) // #nosec G304 -- test fixture
	got, _ := os.ReadFile(filepath.Join(dir, layout.FilePublicKey))       // #nosec G304 -- test fixture
	if !bytes.Equal(want, got) {
		t.Fatal("the recovered public key is not the one whose private key was published")
	}
}

func TestRecoverPartial_withoutAMatchingStagingRefusesWithSafeAdvice(t *testing.T) {
	dir := t.TempDir()
	owner := mustSeed(t, filepath.Join(t.TempDir(), "owner"))
	copyFile(t, filepath.Join(owner, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	err := RecoverPartial(dir, silentLog{})
	if err == nil {
		t.Fatal("a partial set with nothing to recover from was accepted")
	}
	for _, want := range []string{"inconsistent state", "restore the missing file(s) from a backup", "must not be deleted or regenerated"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "delete all key files") {
		t.Errorf("the refusal advises deleting every key file: %v", err)
	}
}

func TestTryRecover_aCompleteSetNeedsNothing(t *testing.T) {
	dir := mustSeed(t, t.TempDir())
	if err := TryRecover(dir, silentLog{}); err != nil {
		t.Fatalf("TryRecover on a complete set: %v", err)
	}
}
