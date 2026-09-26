// Permission warning on the load paths.
//
// A Podman secret mounted without an explicit `mode` arrives as a regular file
// at mode 0444 owned by root, and a Kubernetes Secret volume defaults to
// 0644. authcore has been loading the private key and the refresh secret from
// such files without comment; this file pins the warn-only behaviour the
// helper in modecheck.go ships with.

package keymanager_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// modeWarnTag is the marker the warn helper prefixes its message with. Tests
// scope their counts to it so an unrelated Warn (gitignore, metadata, leftover
// staging) does not pollute the assertion.
const modeWarnTag = "by group or others"

// modeWarnLogger captures Warn calls so a test can assert on what was logged.
// It mirrors the recorder that lives in the internal test helpers and only
// keeps what the assertion needs: the formatted message for each Warn.
type modeWarnLogger struct {
	mu   sync.Mutex
	warn []string
}

func (l *modeWarnLogger) Info(string, ...any) {}

func (l *modeWarnLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warn = append(l.warn, fmt.Sprintf(msg, args...))
}

// modeWarnEntries returns the captured Warn messages formatted with their
// arguments, in the order they were logged.
func (l *modeWarnLogger) modeWarnEntries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.warn))
	copy(out, l.warn)
	return out
}

// countModeWarns returns how many of the captured Warns carry the marker the
// permission helper uses. Other Warn calls in the load path (gitignore,
// metadata, leftover staging) are ignored.
func (l *modeWarnLogger) countModeWarns() int {
	n := 0
	for _, w := range l.modeWarnEntries() {
		if strings.Contains(w, modeWarnTag) {
			n++
		}
	}
	return n
}

// a complete set created by New, then the private key chmod-ed to 0644,
// logs exactly one mode Warn that names the private key path and "0644". The
// public key at 0644 must not produce a Warn (it is meant to be shared).
func TestModeWarn_PrivateKeyGroupOrWorldReadable_New_LogsOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	log := testLogger{t}
	if _, err := keymanager.New(dir, log); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	privPath := filepath.Join(dir, "ed25519_private.pem")
	if err := os.Chmod(privPath, 0644); err != nil {
		t.Fatalf("chmod private key 0644: %v", err)
	}

	capture := &modeWarnLogger{}
	if _, err := keymanager.New(dir, capture); err != nil {
		t.Fatalf("second keymanager.New(): %v", err)
	}

	entries := capture.modeWarnEntries()
	if got := capture.countModeWarns(); got != 1 {
		t.Fatalf("mode Warns from New = %d, want 1; entries: %v", got, entries)
	}

	msg := entries[0]
	if !strings.Contains(msg, privPath) {
		t.Errorf("mode Warn does not name the private key path %q: %q", privPath, msg)
	}
	if !strings.Contains(msg, "0644") {
		t.Errorf("mode Warn does not mention the actual mode 0644: %q", msg)
	}

	for _, e := range entries {
		if strings.Contains(e, "ed25519_public.pem") {
			t.Errorf("mode Warn must not mention the public key path: %q", e)
		}
	}
}

// a complete set with refresh_secret.key chmod-ed to 0640, loaded via
// Load (the load-only entry point), logs exactly one mode Warn naming it and
// "0640".
func TestModeWarn_RefreshSecretGroupOrWorldReadable_Load_LogsOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	secretPath := filepath.Join(dir, "refresh_secret.key")
	if err := os.Chmod(secretPath, 0640); err != nil {
		t.Fatalf("chmod refresh secret 0640: %v", err)
	}

	capture := &modeWarnLogger{}
	if _, err := keymanager.Load(dir, capture); err != nil {
		t.Fatalf("keymanager.Load(): %v", err)
	}

	entries := capture.modeWarnEntries()
	if got := capture.countModeWarns(); got != 1 {
		t.Fatalf("mode Warns from Load = %d, want 1; entries: %v", got, entries)
	}

	msg := entries[0]
	if !strings.Contains(msg, secretPath) {
		t.Errorf("mode Warn does not name the refresh secret path %q: %q", secretPath, msg)
	}
	if !strings.Contains(msg, "0640") {
		t.Errorf("mode Warn does not mention the actual mode 0640: %q", msg)
	}
}

// a complete set where the private key and the refresh secret are still
// at 0600 logs zero mode Warns.
func TestModeWarn_TightPermissions_LogsNone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	capture := &modeWarnLogger{}
	if _, err := keymanager.New(dir, capture); err != nil {
		t.Fatalf("second keymanager.New(): %v", err)
	}

	if got := capture.countModeWarns(); got != 0 {
		t.Errorf("mode Warns = %d, want 0 for 0600 files; entries: %v", got, capture.modeWarnEntries())
	}
}

// a private key at 0400 reached through a symlink whose own mode is
// 0777 logs zero mode Warns. The mode that matters is the target's, since
// the Kubernetes Secret mount path projects every key file as a symlink.
func TestModeWarn_SymlinkFollowsTargetMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	// Seed a complete set, then move the real private key out to a
	// separate directory at 0400 and replace its slot in KeysDir with a
	// symlink to it. A fresh symlink on Linux reports 0777 to Lstat; the
	// target file is the one that is read via Stat, and it stays at 0400.
	// Chmod-ing the symlink itself would chmod the target, which is why
	// no chmod is issued here.
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	realDir := t.TempDir()
	realPath := filepath.Join(realDir, "private.pem")
	srcPath := filepath.Join(dir, "ed25519_private.pem")

	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read original private key: %v", err)
	}
	if err := os.WriteFile(realPath, data, 0400); err != nil {
		t.Fatalf("write real private key at 0400: %v", err)
	}
	if err := os.Remove(srcPath); err != nil {
		t.Fatalf("remove original private key: %v", err)
	}
	if err := os.Symlink(realPath, srcPath); err != nil {
		t.Fatalf("symlink private key: %v", err)
	}

	capture := &modeWarnLogger{}
	if _, err := keymanager.New(dir, capture); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	if got := capture.countModeWarns(); got != 0 {
		t.Errorf("mode Warns = %d, want 0 for target mode 0400 through a 0777 symlink; entries: %v",
			got, capture.modeWarnEntries())
	}
}

// a fresh New on an empty directory (generation) logs zero mode Warns.
// authcore wrote the three files itself at 0600; warning about its own
// output would be noise.
func TestModeWarn_FreshGeneration_LogsNone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	capture := &modeWarnLogger{}
	if _, err := keymanager.New(dir, capture); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	if got := capture.countModeWarns(); got != 0 {
		t.Errorf("mode Warns = %d, want 0 for a fresh generation; entries: %v",
			got, capture.modeWarnEntries())
	}
}

// the warning helper never changes a mode. After a group-readable key is loaded, the
// private key is still 0644.
func TestModeWarn_NeverChangesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}

	privPath := filepath.Join(dir, "ed25519_private.pem")
	if err := os.Chmod(privPath, 0644); err != nil {
		t.Fatalf("chmod private key 0644: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("second keymanager.New(): %v", err)
	}

	fi, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0644 {
		t.Errorf("private key mode after New = %04o, want 0644 (unchanged)", got)
	}
}
