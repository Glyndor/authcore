package bootstrap_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
)

// seededDir returns a key directory that already holds its key material.
func seededDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("seed bootstraptest.New(): %v", err)
	}
	return dir
}

func modeOf(t *testing.T, dir string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	return fi.Mode().Perm()
}

// An operator who hands authcore a deliberately tighter KeysDir keeps it. This
// directory holds the Ed25519 private key and the refresh secret, so widening
// its permissions unasked is the opposite of what the tightening exists for.
func TestNew_doesNotLoosenARestrictiveKeysDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := seededDir(t)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New(): %v", err)
	}

	if got := modeOf(t, dir); got != 0500 {
		t.Errorf("key directory mode = %04o, want 0500 left alone", got)
	}
}

// The tightening the comment exists for still has to happen: a volume-mounted
// or pre-created directory that arrives world-readable is closed to the owner.
func TestNew_tightensAnOpenKeysDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := seededDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("loosen directory: %v", err)
	}

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New(): %v", err)
	}

	if got := modeOf(t, dir); got != 0700 {
		t.Errorf("key directory mode = %04o, want 0700 after tightening", got)
	}
}

// The permission warning on both load paths, for both secret files, at every
// mode that opens the file to others. Before 2026-09-25 the suite pinned the
// private key on New and the refresh secret on Load only, and read bits only:
// the crossed pairs and the write-only modes (0602, 0620) loaded silently.
func TestModeWarn_everyPathEveryFileEveryOpenMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	paths := map[string]func(string, *modeWarnLogger) error{
		"New":  func(dir string, l *modeWarnLogger) error { _, err := bootstraptest.New(dir, l); return err },
		"Load": func(dir string, l *modeWarnLogger) error { _, err := bootstraptest.Load(dir, l); return err },
	}
	for pathName, open := range paths {
		for _, file := range []string{"ed25519_private.pem", "refresh_secret.key"} {
			for _, mode := range []os.FileMode{0o640, 0o604, 0o602, 0o620, 0o600, 0o400} {
				t.Run(fmt.Sprintf("%s/%s/%04o", pathName, file, mode), func(t *testing.T) {
					dir := seededDir(t)
					target := filepath.Join(dir, file)
					if err := os.Chmod(target, mode); err != nil {
						t.Fatal(err)
					}
					capture := &modeWarnLogger{}
					if err := open(dir, capture); err != nil {
						t.Fatalf("%s: %v", pathName, err)
					}
					want := 0
					if mode&0o066 != 0 {
						want = 1
					}
					got := capture.countModeWarns()
					if got != want {
						t.Fatalf("mode warns = %d, want %d; entries: %q", got, want, capture.modeWarnEntries())
					}
					if want == 1 && !strings.Contains(capture.modeWarnEntries()[0], target) {
						t.Fatalf("the warning does not name %s: %q", target, capture.modeWarnEntries())
					}
				})
			}
		}
	}
}

// Load warns when KeysDir itself can be written by others without the sticky
// bit, which is where a key file could be replaced. New tightens the
// directory instead; Load never touches it, and said nothing until
// 2026-09-25. A sticky 1777 directory is a Kubernetes Secret mount and is
// not reported.
func TestModeWarn_LoadReportsAWritableKeysDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix mode bits and a non-root user")
	}
	for mode, want := range map[os.FileMode]int{
		0o777:                 1,
		0o733:                 1,
		0o700 | os.ModeSticky: 0,
		0o777 | os.ModeSticky: 0,
		0o700:                 0,
		0o750:                 0,
	} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			dir := seededDir(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			capture := &modeWarnLogger{}
			if _, err := bootstraptest.Load(dir, capture); err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := 0
			for _, w := range capture.modeWarnEntries() {
				if strings.Contains(w, "key directory") && strings.Contains(w, "writable by group or others") {
					got++
				}
			}
			if got != want {
				t.Fatalf("directory warns = %d, want %d; entries: %q", got, want, capture.modeWarnEntries())
			}
			if fi, _ := os.Stat(dir); fi.Mode().Perm() != mode.Perm() {
				t.Fatalf("Load changed the directory mode to %04o", fi.Mode().Perm())
			}
		})
	}
}

// Permission warning on the load paths.
//
// A Podman secret mounted without an explicit `mode` arrives as a regular file
// at mode 0444 owned by root, and a Kubernetes Secret volume defaults to
// 0644. authcore has been loading the private key and the refresh secret from
// such files without comment; this file pins the warn-only behaviour the
// helper in modecheck.go ships with.
