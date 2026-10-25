package modecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type recorder struct{ warnings []string }

func (r *recorder) Info(string, ...any) {}
func (r *recorder) Warn(msg string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(msg, args...))
}

func unixOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
}

func fileAt(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWarnIfReadableByOthers_warnsOnceForEveryOpenMode(t *testing.T) {
	unixOnly(t)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o444, 0o620, 0o602, 0o666} {
		log := &recorder{}
		WarnIfReadableByOthers(fileAt(t, mode), log)
		if len(log.warnings) != 1 {
			t.Errorf("mode %04o: %d warnings, want 1 (%q)", mode, len(log.warnings), log.warnings)
		}
	}
}

func TestWarnIfReadableByOthers_silentForTightModes(t *testing.T) {
	unixOnly(t)
	for _, mode := range []os.FileMode{0o600, 0o400} {
		log := &recorder{}
		WarnIfReadableByOthers(fileAt(t, mode), log)
		if len(log.warnings) != 0 {
			t.Errorf("mode %04o warned: %q", mode, log.warnings)
		}
	}
}

func TestWarnIfReadableByOthers_neverChangesTheMode(t *testing.T) {
	unixOnly(t)
	path := fileAt(t, 0o644)
	WarnIfReadableByOthers(path, &recorder{})
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode after the check = %v, %v; want 0644 untouched", fi.Mode().Perm(), err)
	}
}

// A path that cannot be statted is left to the loader's own error.
func TestWarnIfReadableByOthers_missingPathIsSilent(t *testing.T) {
	log := &recorder{}
	WarnIfReadableByOthers(filepath.Join(t.TempDir(), "absent"), log)
	if len(log.warnings) != 0 {
		t.Fatalf("warned about a missing file: %q", log.warnings)
	}
}

func TestWarnIfDirWritableByOthers(t *testing.T) {
	unixOnly(t)
	for _, tc := range []struct {
		mode os.FileMode
		warn bool
	}{
		{0o700, false},
		{0o755, false},
		{0o775, true},
		{0o757, true},
		{0o777, true},
		{0o777 | os.ModeSticky, false}, // what Kubernetes mounts a Secret under
	} {
		dir := t.TempDir()
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		log := &recorder{}
		WarnIfDirWritableByOthers(dir, log)
		if got := len(log.warnings) == 1; got != tc.warn || len(log.warnings) > 1 {
			t.Errorf("mode %v: warnings %q, want warn=%v", tc.mode, log.warnings, tc.warn)
		}
		_ = os.Chmod(dir, 0o700)
	}
}

func TestWarnIfDirWritableByOthers_missingPathIsSilent(t *testing.T) {
	log := &recorder{}
	WarnIfDirWritableByOthers(filepath.Join(t.TempDir(), "absent"), log)
	if len(log.warnings) != 0 {
		t.Fatalf("warned about a missing directory: %q", log.warnings)
	}
}

// TightenDirMode only ever tightens. os.Chmod(dir, DirMode) instead of
// mode&DirMode survived: a 0555 directory gained owner write.
func TestTightenDirMode_onlyEverTightens(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix mode bits and a non-root user")
	}
	for _, tc := range []struct{ before, after os.FileMode }{
		{0o555, 0o500}, // strips group and other, never adds owner write
		{0o750, 0o700},
		{0o755, 0o700},
		{0o500, 0o500},
		{0o700, 0o700},
	} {
		dir := t.TempDir()
		if err := os.Chmod(dir, tc.before); err != nil {
			t.Fatal(err)
		}
		if err := TightenDirMode(dir); err != nil {
			t.Fatalf("TightenDirMode on a %04o directory: %v", tc.before, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != tc.after {
			t.Errorf("dir %04o after TightenDirMode is %04o, want %04o", tc.before, fi.Mode().Perm(), tc.after)
		}
		_ = os.Chmod(dir, 0o700)
	}
}

func TestTightenDirMode_missingDirectoryIsAnError(t *testing.T) {
	if err := TightenDirMode(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("TightenDirMode on a missing directory returned no error")
	}
}
