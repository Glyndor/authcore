package modecheck_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/modecheck"
)

type warnings struct{ n int }

func (w *warnings) Info(string, ...any) {}
func (w *warnings) Warn(string, ...any) { w.n++ }

// Only read and write bits for group and others are a finding; execute bits
// on a file that is not executed are not.
func TestWarnIfReadableByOthers_IgnoresExecuteBits(t *testing.T) {
	cases := []struct {
		mode os.FileMode
		warn bool
	}{
		{0o600, false},
		{0o601, false},
		{0o610, false},
		{0o640, true},
		{0o604, true},
		{0o620, true},
		{0o602, true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%04o", c.mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, c.mode); err != nil {
				t.Fatal(err)
			}
			var w warnings
			modecheck.WarnIfReadableByOthers(path, &w)
			if (w.n > 0) != c.warn {
				t.Fatalf("mode %04o: %d warning(s), want warning=%v", c.mode, w.n, c.warn)
			}
		})
	}
}

// A directory whose only excess bit is "others may search" is still looser
// than owner-only and is tightened to 0700.
func TestTightenDirMode_RemovesALoneOtherExecuteBit(t *testing.T) {
	for _, mode := range []os.FileMode{0o701, 0o710, 0o755, 0o770} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := modecheck.TightenDirMode(dir); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o700 {
			t.Errorf("from %04o: mode = %04o, want 0700", mode, got)
		}
	}
}

// A directory with no owner bits at all is still tightened: nothing outside
// 0700 stays, and the owner can restore access by hand.
func TestTightenDirMode_StripsGroupAndOtherBitsFromADirectoryWithoutOwnerBits(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := os.Chmod(dir, 0o055); err != nil {
		t.Fatal(err)
	}
	if err := modecheck.TightenDirMode(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0 {
		t.Fatalf("mode = %04o, want 0000", got)
	}
}
