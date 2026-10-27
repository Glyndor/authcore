package wait

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// waitTimeoutError's "present" branch: when the wait expires on a dir that
// holds some keys but never reaches a complete set, the message must name
// what is present and what is missing.
func TestWaitTimeoutError_namesPresentAndMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wait timing depends on POSIX file semantics")
	}

	dir := t.TempDir()
	if err := recoverytest.SeedKeys(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	prevWait, prevPoll := publishWait, publishPoll
	publishWait = 20 * time.Millisecond
	publishPoll = 2 * time.Millisecond
	t.Cleanup(func() {
		publishWait, publishPoll = prevWait, prevPoll
	})

	err := ForSet(dir, recoverytest.SilentLog{})
	if err == nil {
		t.Fatal("ForSet returned nil on a partial set")
	}
	msg := err.Error()
	if !strings.Contains(msg, layout.FilePrivateKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePrivateKey, err)
	}
	if !strings.Contains(msg, layout.FilePublicKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePublicKey, err)
	}
}

func TestWaitExpiresWithAccurateMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wait timing depends on POSIX file semantics")
	}
	dir := t.TempDir()

	prevWait, prevPoll := publishWait, publishPoll
	publishWait = 50 * time.Millisecond
	publishPoll = 5 * time.Millisecond
	t.Cleanup(func() {
		publishWait, publishPoll = prevWait, prevPoll
	})

	start := time.Now()
	err := ForSet(dir, recoverytest.SilentLog{})
	elapsed := time.Since(start)
	// The clock is a safety net on top of the window the wait was given,
	// and it scales with that window: a runner that is slow does not fail
	// the test for having stretched a 50 ms window.
	if elapsed > 100*publishWait {
		t.Errorf("wait exceeded %v on an empty dir: %v", 100*publishWait, elapsed)
	}
	// The wait must not give up before its window: a refusal that arrives
	// early is not the expiry this test is about.
	if elapsed < publishWait {
		t.Errorf("wait gave up after %v, before its %v window", elapsed, publishWait)
	}
	if err == nil {
		t.Fatal("ForSet returned nil on an empty dir")
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("error must say 'did not finish', got: %v", err)
	}
	if strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must not mention symlinks, got: %v", err)
	}
}

func TestForSet_returnsAsSoonAsTheSetIsComplete(t *testing.T) {
	dir := recoverytest.MustSeed(t, t.TempDir())
	window := publishWait
	// Baseline: what one recovery pass costs on this machine, measured in
	// this test, so the bound below scales with the runner instead of being
	// a fixed number.
	baseStart := time.Now()
	if err := recovery.TryRecover(dir, recoverytest.SilentLog{}); err != nil {
		t.Fatalf("TryRecover on a complete set: %v", err)
	}
	baseline := time.Since(baseStart)

	start := time.Now()
	if err := ForSet(dir, recoverytest.SilentLog{}); err != nil {
		t.Fatalf("ForSet: %v", err)
	}
	// The wait must not cost a significant fraction of the window it waits
	// for: on a complete set it returns on the first recovery pass. The
	// floor keeps the bound from ever being tighter than it was.
	limit := max(20*baseline, window/5)
	if elapsed := time.Since(start); elapsed > limit {
		t.Errorf("ForSet waited on a set that was already complete: %v, limit %v", elapsed, limit)
	}
}

func TestForSet_finishesAPublishItFindsHalfDone(t *testing.T) {
	recoverytest.PosixOnly(t)
	base := t.TempDir()
	owner := recoverytest.MustSeed(t, filepath.Join(base, "owner"))
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	recoverytest.StagingFrom(t, dir, "aaaaaaaaaaaaaaaa", owner)
	recoverytest.CopyFile(t, filepath.Join(owner, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))

	if err := ForSet(dir, recoverytest.SilentLog{}); err != nil {
		t.Fatalf("ForSet: %v", err)
	}
	if !recoverytest.Complete(t, dir) {
		t.Fatal("the set is still partial")
	}
}

// ForSet's "TryRecover returned a non-ErrNoMatchingStaging error" branch.
// Set up a partial set whose matching staging holds the private key bytes of
// the published private key but a public key from a different initialisation:
// findMatchingStaging picks the staging, completeFromStaging's pass-one byte
// comparison finds the public key differs and returns a non-ErrNoMatchingStaging
// error. ForSet must surface that error instead of looping.
func TestForSet_propagatesNonMatchingStagingError(t *testing.T) {
	recoverytest.PosixOnly(t)

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerA := filepath.Join(base, "ownerA")
	if err := recoverytest.SeedKeys(ownerA); err != nil {
		t.Fatal(err)
	}
	ownerB := filepath.Join(base, "ownerB")
	if err := recoverytest.SeedKeys(ownerB); err != nil {
		t.Fatal(err)
	}

	stagingA := filepath.Join(dir, ".staging-aabbccddeeff00112233")
	if err := os.MkdirAll(stagingA, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		recoverytest.CopyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	recoverytest.CopyFile(t, filepath.Join(stagingA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	recoverytest.CopyFile(t, filepath.Join(ownerB, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))

	err := ForSet(dir, recoverytest.SilentLog{})
	if err == nil {
		t.Fatal("ForSet returned nil on a partial set whose staging holds different bytes")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error from pass-one, got: %v", err)
	}
}
