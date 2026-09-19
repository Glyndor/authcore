package keymanager

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These cover the recovery path: findMatchingStaging's filter branches
// (incomplete, symlinked, valid) and recoverPartial's "set completes
// between checks" branch. Each test restores the recovery hooks it sets.

// findMatchingStaging's filter branches. One staging dir is missing the
// refresh secret, one has its ed25519_public.pem as a symlink, and one is
// valid and matches the published private key. Only the valid one is
// returned; removing it makes findMatchingStaging return errNoMatchingStaging.
func TestFindMatchingStagingSkipsIncompleteAndSymlinkedFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}

	owner := filepath.Join(base, "owner")
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(dir, name))
	}

	incomplete := filepath.Join(dir, ".staging-99998888777766665555")
	if err := os.MkdirAll(incomplete, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(incomplete, name))
	}

	symlinked := filepath.Join(dir, ".staging-aaaa1111bbbb2222cccc")
	if err := os.MkdirAll(symlinked, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(symlinked, name))
	}
	if err := os.Symlink(filepath.Join(owner, filePublicKey), filepath.Join(symlinked, filePublicKey)); err != nil {
		t.Fatal(err)
	}

	valid := filepath.Join(dir, ".staging-dddd3333eeee4444ffff")
	if err := os.MkdirAll(valid, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(valid, name))
	}

	got, err := findMatchingStaging(dir)
	if err != nil {
		t.Fatalf("findMatchingStaging: %v", err)
	}
	if got != valid {
		t.Errorf("findMatchingStaging returned %q, want %q", got, valid)
	}

	if err := os.RemoveAll(valid); err != nil {
		t.Fatal(err)
	}
	got, err = findMatchingStaging(dir)
	if !errors.Is(err, errNoMatchingStaging) {
		t.Fatalf("findMatchingStaging after removal: want errNoMatchingStaging, got %v (path %q)", err, got)
	}
	if got != "" {
		t.Errorf("findMatchingStaging returned a non-empty path %q with errNoMatchingStaging", got)
	}
}

// recoverPartial's "set completes between checks" branch. The first
// tryRecover inspects a partial set with no matching staging, returns
// errNoMatchingStaging; recoverPartialBetweenChecksHook completes the set
// before the second inspection; recoverPartial then sees setComplete and
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
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}

	copyFile(t, filepath.Join(owner, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(owner, filePublicKey), filepath.Join(dir, filePublicKey))

	prev := recoverPartialBetweenChecksHook
	t.Cleanup(func() { recoverPartialBetweenChecksHook = prev })
	recoverPartialBetweenChecksHook = func() {
		copyFile(t, filepath.Join(owner, fileRefreshSecret), filepath.Join(dir, fileRefreshSecret))
	}

	if err := recoverPartial(dir, silentLog{}); err != nil {
		t.Fatalf("recoverPartial refused a set completed between checks: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
}

// findMatchingStaging's "no published private key" branch: when no private
// key is published yet, findMatchingStaging adopts the staging directory
// without comparing bytes. This is the recovery entrypoint before any file
// has reached KeysDir.
func TestFindMatchingStaging_returnsStagingWhenNoPrivateKeyIsPublished(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-cccc2222dddd3333eeee")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}

	got, err := findMatchingStaging(dir)
	if err != nil {
		t.Fatalf("findMatchingStaging: %v", err)
	}
	if got != staging {
		t.Errorf("findMatchingStaging returned %q, want %q", got, staging)
	}
}

// findMatchingStaging's fileBytesIfExists error branch: an oversized published
// private key must surface the cap error rather than report a false match.
func TestFindMatchingStaging_oversizedPublishedPrivateKeyIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(base, "owner")
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-eeee3333ffff4444aaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(staging, name))
	}
	oversized := make([]byte, maxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), oversized, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := findMatchingStaging(dir)
	if err == nil {
		t.Fatal("findMatchingStaging succeeded despite an oversized published private key")
	}
	if got != "" {
		t.Errorf("findMatchingStaging returned a non-empty path %q with an error", got)
	}
}

// tryRecover's inspect-error branch: a hostile entry inside a partial set
// must surface the inspect error before any recovery is attempted. New
// refuses a hostile set at the entry inspectKeySet, so this test drives
// tryRecover directly.
func TestTryRecover_inspectErrorIsReturned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, filePublicKey)); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, filePublicKey)
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	err := tryRecover(dir, silentLog{})
	if err == nil {
		t.Fatal("tryRecover succeeded despite a hostile entry")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error must come from inspect, got: %v", err)
	}
}

// recoverPartial's "second inspect surfaces an error after the hook" branch.
// The first tryRecover sees a partial set with no matching staging and
// returns errNoMatchingStaging. The hook then plants a hostile entry (a
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
	if _, err := New(owner, silentLog{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey} {
		copyFile(t, filepath.Join(owner, name), filepath.Join(dir, name))
	}

	prev := recoverPartialBetweenChecksHook
	t.Cleanup(func() { recoverPartialBetweenChecksHook = prev })
	recoverPartialBetweenChecksHook = func() {
		loop := filepath.Join(dir, fileRefreshSecret)
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
	}

	err := recoverPartial(dir, silentLog{})
	if err == nil {
		t.Fatal("recoverPartial succeeded despite a hostile entry after the hook")
	}
	if !strings.Contains(err.Error(), "inspecting") {
		t.Errorf("error must come from inspect, got: %v", err)
	}
}

// waitForSet's "tryRecover returned a non-errNoMatchingStaging error" branch.
// Set up a partial set whose matching staging holds the private key bytes of
// the published private key but a public key from a different initialisation:
// findMatchingStaging picks the staging, completeFromStaging's pass-one byte
// comparison finds the public key differs and returns a non-errNoMatchingStaging
// error. waitForSet must surface that error instead of looping.
func TestWaitForSet_propagatesNonMatchingStagingError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownerA := filepath.Join(base, "ownerA")
	if _, err := New(ownerA, silentLog{}); err != nil {
		t.Fatal(err)
	}
	ownerB := filepath.Join(base, "ownerB")
	if _, err := New(ownerB, silentLog{}); err != nil {
		t.Fatal(err)
	}

	stagingA := filepath.Join(dir, ".staging-aabbccddeeff00112233")
	if err := os.MkdirAll(stagingA, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	copyFile(t, filepath.Join(stagingA, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(ownerB, filePublicKey), filepath.Join(dir, filePublicKey))

	err := waitForSet(dir, silentLog{})
	if err == nil {
		t.Fatal("waitForSet returned nil on a partial set whose staging holds different bytes")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error from pass-one, got: %v", err)
	}
}
