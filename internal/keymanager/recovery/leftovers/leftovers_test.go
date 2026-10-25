package leftovers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

func TestReport_readOnlyKeysDirIsHandled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory read permissions")
	}

	dir := t.TempDir()
	if err := recoverytest.SeedKeys(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	log := recoverytest.SilentLog{}
	Report(dir, log) // must not panic, must not return an error path
}

func TestReport_handlesHostileEntry(t *testing.T) {
	dir := t.TempDir()
	if err := recoverytest.SeedKeys(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaa"), []byte("not a dir"), 0600); err != nil {
		t.Fatal(err)
	}
	Report(dir, recoverytest.SilentLog{}) // must not panic
}

// Report' "incomplete staging directory" branch. A complete
// published set plus a .staging-<hex> directory holding only the private key
// must produce exactly one Warn naming that staging directory as incomplete,
// and the directory must still exist on disk afterwards.
func TestReportWarnsOnIncompleteStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	if err := recoverytest.SeedKeys(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}

	incomplete := filepath.Join(dir, ".staging-deadbeefcafef00d")
	if err := os.MkdirAll(incomplete, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incomplete, layout.FilePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}

	log := &recoverytest.RecordingLog{}
	Report(dir, log)

	warned := 0
	for _, msg := range log.Warns {
		if strings.Contains(msg, "is incomplete") && strings.Contains(msg, incomplete) {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("want exactly one incomplete-staging Warn, got %d (entries: %v)", warned, log.Warns)
	}
	if _, err := os.Stat(incomplete); err != nil {
		t.Errorf("incomplete staging directory was deleted: %v", err)
	}
}

func TestReport_aCopyOfThePublishedKeysIsReported(t *testing.T) {
	dir := recoverytest.MustSeed(t, t.TempDir())
	staging := recoverytest.StagingFrom(t, dir, "1111111111111111", dir)

	log := &recoverytest.RecordingLog{}
	Report(dir, log)

	if !log.WarnContains("holds a copy of the published keys") || !log.WarnContains(staging) {
		t.Errorf("no warning naming the copy; got %v", log.Warns)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("Report must never delete: %v", err)
	}
}

func TestReport_keysThatWereNeverPublishedAreReported(t *testing.T) {
	dir := recoverytest.MustSeed(t, t.TempDir())
	other := recoverytest.MustSeed(t, filepath.Join(t.TempDir(), "other"))
	staging := recoverytest.StagingFrom(t, dir, "2222222222222222", other)

	log := &recoverytest.RecordingLog{}
	Report(dir, log)

	if !log.WarnContains("holds keys that were never published") || !log.WarnContains(staging) {
		t.Errorf("no warning for unpublished keys; got %v", log.Warns)
	}
}

func TestReport_aCleanDirectoryIsSilent(t *testing.T) {
	log := &recoverytest.RecordingLog{}
	Report(recoverytest.MustSeed(t, t.TempDir()), log)
	if len(log.Warns) != 0 {
		t.Errorf("warned about a clean directory: %v", log.Warns)
	}
}
