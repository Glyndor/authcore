package keyload

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// replaceSet swaps a freshly generated set into dir, file by file, each by
// rename so every file gets a new inode, and returns the set.
func replaceSet(t *testing.T, dir string) keyloadtest.KeySet {
	t.Helper()
	staging := t.TempDir()
	set := keyloadtest.WriteSet(t, staging)
	for _, name := range layout.KeyFileNames() {
		if err := os.Rename(filepath.Join(staging, name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

// hooks installs a test hook for one test and removes it, with no pause. The
// hook is called after every file read; lastFile is the call that follows the
// third file, after which nothing is left to read.
func hooks(t *testing.T, f func(attempt, file int)) {
	t.Helper()
	oldPause, oldHook := retryPause, seams.AfterKeyRead
	retryPause, seams.AfterKeyRead = 0, f
	t.Cleanup(func() { retryPause, seams.AfterKeyRead = oldPause, oldHook })
}

// lastFile is the index of the refresh secret, the last file read.
const lastFile = 2

// afterAllRead adapts f to run once per attempt, when all three files are read.
func afterAllRead(f func(attempt int)) func(attempt, file int) {
	return func(attempt, file int) {
		if file == lastFile && f != nil {
			f(attempt)
		}
	}
}

func TestFiles_repeatsTheReadWhenTheSetIsReplacedDuringIt(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	var current keyloadtest.KeySet
	attempts := 0
	hooks(t, afterAllRead(func(attempt int) {
		attempts++
		if attempt == 0 {
			current = replaceSet(t, dir)
		}
	}))

	priv, pub, secret, err := Files(dir, keyloadtest.SilentLog{})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if attempts != 2 {
		t.Errorf("read %d times, want 2", attempts)
	}
	if !priv.Equal(current.Priv) || !pub.Equal(current.Pub) || string(secret) != string(current.Secret) {
		t.Fatal("the result is not the whole replacement set")
	}
}

func TestFiles_refusesASetThatNeverSettles(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	attempts := 0
	hooks(t, afterAllRead(func(int) { attempts++; replaceSet(t, dir) }))

	_, _, _, err := Files(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "changed while they were being read") {
		t.Fatalf("Files = %v, want the changed-while-reading refusal", err)
	}
	if attempts != readAttempts {
		t.Errorf("read %d times, want %d", attempts, readAttempts)
	}
	if strings.Contains(err.Error(), "delete") {
		t.Errorf("the refusal advises deleting: %v", err)
	}
}

func TestFiles_aFailureOfTheReadItselfIsNotRepeatedWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FileRefreshSecret, []byte("not hex\n"), 0600)
	attempts := 0
	hooks(t, afterAllRead(func(int) { attempts++ }))

	if _, _, _, err := Files(dir, keyloadtest.SilentLog{}); err == nil || !strings.Contains(err.Error(), "not hex encoded") {
		t.Fatalf("Files = %v, want the not-hex refusal", err)
	}
	if attempts != 1 {
		t.Errorf("read %d times, want 1", attempts)
	}
}

func TestFiles_anOversizedFileIsRefusedWithoutRepeating(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FilePublicKey, make([]byte, layout.MaxKeyFileSize+1), 0600)
	reads := 0
	hooks(t, func(int, int) { reads++ })

	if _, _, _, err := Files(dir, keyloadtest.SilentLog{}); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("Files = %v, want the size refusal", err)
	}
	if reads != 1 {
		t.Errorf("read %d files, want only the private key before the refusal", reads)
	}
}

func TestFiles_aMissingFileKeepsItsOwnError(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}
	hooks(t, nil)

	_, _, _, err := Files(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "refresh secret") || strings.Contains(err.Error(), "changed while") {
		t.Fatalf("Files = %v, want the read error", err)
	}
}

func TestFiles_aFileThatVanishesAfterTheReadIsNotVouchedFor(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	hooks(t, afterAllRead(func(int) { _ = os.Remove(filepath.Join(dir, layout.FileRefreshSecret)) }))

	if _, _, _, err := Files(dir, keyloadtest.SilentLog{}); err == nil {
		t.Fatal("Files accepted a set it could not inspect after reading")
	}
}

func TestFiles_aFileThatVanishesAfterTheReadIsReadAgainWhenItComesBack(t *testing.T) {
	dir := t.TempDir()
	set := keyloadtest.WriteSet(t, dir)
	hooks(t, afterAllRead(func(attempt int) {
		if attempt == 0 {
			keyloadtest.Put(t, dir, layout.FileRefreshSecret, []byte(hex.EncodeToString(set.Secret)+"\n"), 0600)
		}
	}))

	if _, _, secret, err := Files(dir, keyloadtest.SilentLog{}); err != nil || string(secret) != string(set.Secret) {
		t.Fatalf("Files = %v, want the settled set", err)
	}
}
