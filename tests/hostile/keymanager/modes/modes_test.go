//go:build unix

// Package modes attacks the key store through permissions, special mode bits,
// a hostile umask and mode changes while a start is running.
package modes

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 3: permissions, special mode bits and a hostile umask.

func TestHostile_Modes_newTightensALaxDirectoryAndLoadOnlyWarnsWithoutTouchingIt(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, mode := range []os.FileMode{0o777, 0o775, 0o757, 0o755, 0o770, 0o720, 0o702} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.WithSet(t, s)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}

			ro := hostiletest.Open(t, dir, true)
			hostiletest.Loaded(t, ro, s)
			wantWarn := mode&0o022 != 0
			if ro.Log.Has("writable by group or others") != wantWarn {
				t.Errorf("load-only warned=%v for a directory at %04o, want %v:\n%s", !wantWarn, mode, wantWarn, ro.Log.All())
			}
			if got := hostiletest.ModeOf(t, dir).Perm(); got != mode {
				t.Errorf("load-only changed the directory mode from %04o to %04o", mode, got)
			}

			hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
			if got := hostiletest.ModeOf(t, dir).Perm(); got != 0o700 {
				t.Errorf("New left the key directory at %04o, want 0700", got)
			}
		})
	}
}

func TestHostile_Modes_stickyWorldWritableDirectoryIsNotReported(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	r := hostiletest.Open(t, dir, true)
	hostiletest.Loaded(t, r, s)
	if r.Log.Has("writable by group or others") {
		t.Error("a sticky 1777 directory, which is how a Secret volume is mounted, was reported")
	}
}

func TestHostile_Modes_stricterDirectoryIsNeverRaised(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	hostiletest.RestoreMode(t, dir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	r := hostiletest.Open(t, dir, false)

	hostiletest.Loaded(t, r, s)
	if got := hostiletest.ModeOf(t, dir).Perm(); got != 0o500 {
		t.Errorf("a read-only key directory was changed to %04o", got)
	}
	if !r.Log.Has("metadata.json") {
		t.Error("the failure to record metadata in a read-only directory was not reported")
	}
}

func TestHostile_Modes_laxKeyFilesLoadWithAWarningAndAreNeverChmodded(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	cases := []struct {
		mode os.FileMode
		warn bool
	}{
		{0o600, false}, {0o400, false}, {0o640, true}, {0o644, true}, {0o660, true},
		{0o666, true}, {0o602, true}, {0o604, true}, {0o444, true}, {0o440, true},
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%04o", name, c.mode), func(t *testing.T) {
				hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
					sb := hostiletest.NewSandbox(t)
					s := hostiletest.NewSet(t)
					dir := sb.WithSet(t, s)
					path := filepath.Join(dir, name)
					if err := os.Chmod(path, c.mode); err != nil {
						t.Fatal(err)
					}

					r := hostiletest.Open(t, dir, loadOnly)

					hostiletest.Loaded(t, r, s)
					if got := r.Log.Has("readable or writable by group or others"); got != c.warn {
						t.Errorf("mode %04o: warned=%v, want %v\n%s", c.mode, got, c.warn, r.Log.All())
					}
					if got := hostiletest.ModeOf(t, path).Perm(); got != c.mode {
						t.Errorf("the loader changed %s from %04o to %04o", name, c.mode, got)
					}
				})
			})
		}
	}
}

func TestHostile_Modes_specialBitsOnKeyFilesDoNotChangeWhatLoads(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	bits := map[string]os.FileMode{"setuid": os.ModeSetuid, "setgid": os.ModeSetgid, "sticky": os.ModeSticky}
	for name, bit := range bits {
		t.Run(name, func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				path := filepath.Join(dir, layout.FilePrivateKey)
				if err := os.Chmod(path, 0o600|bit); err != nil {
					t.Fatal(err)
				}

				hostiletest.Loaded(t, hostiletest.Open(t, dir, loadOnly), s)

				if got := hostiletest.ModeOf(t, path); got&bit == 0 || got.Perm() != 0o600 {
					t.Errorf("the loader rewrote the mode: %v", got)
				}
			})
		})
	}
}

func TestHostile_Modes_unreadableKeyFilesAreRefusedNotSkipped(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, name := range layout.KeyFileNames() {
		for _, mode := range []os.FileMode{0o000, 0o200, 0o100} {
			t.Run(fmt.Sprintf("%s/%04o", name, mode), func(t *testing.T) {
				hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
					sb := hostiletest.NewSandbox(t)
					s := hostiletest.NewSet(t)
					dir := sb.WithSet(t, s)
					path := filepath.Join(dir, name)
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
					before := hostiletest.KeyTree(t, dir)

					hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)

					hostiletest.AssertSame(t, "KeysDir", before, hostiletest.KeyTree(t, dir))
				})
			})
		}
	}
}

func TestHostile_Modes_directoryWithoutSearchOrReadPermission(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, mode := range []os.FileMode{0o000, 0o100, 0o200, 0o300, 0o400, 0o500} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				hostiletest.RestoreMode(t, dir)
				if err := os.Chmod(dir, mode); err != nil {
					t.Fatal(err)
				}

				r := hostiletest.Open(t, dir, loadOnly)

				// Either the right set loads or the run is refused. What must
				// never happen is a different set, or a regenerated one.
				if r.Err == nil {
					hostiletest.Loaded(t, r, s)
				} else {
					hostiletest.Refused(t, r, s)
				}
				if err := os.Chmod(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if got := hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey)); string(got) != string(s.PrivPEM) {
					t.Error("the private key on disk was replaced")
				}
			})
		})
	}
}

// withUmask sets the process umask for the rest of the test.
func withUmask(t testing.TB, mask int) {
	t.Helper()
	prev := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(prev) })
}

func TestHostile_Modes_hostileUmaskNeverProducesALaxOrHalfWrittenSet(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, mask := range []int{0o000, 0o022, 0o077, 0o177, 0o277, 0o377, 0o577, 0o777} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			hostiletest.RestoreMode(t, sb.Keys)
			withUmask(t, mask)

			r := hostiletest.Open(t, sb.Keys, false)

			if r.Err == nil {
				for _, n := range []string{layout.FilePrivateKey, layout.FileRefreshSecret, layout.FileMetadata} {
					if got := hostiletest.ModeOf(t, filepath.Join(sb.Keys, n)).Perm(); got&0o077 != 0 {
						t.Errorf("umask %04o produced %s at %04o", mask, n, got)
					}
				}
				if got := hostiletest.ModeOf(t, sb.Keys).Perm(); got&0o077 != 0 {
					t.Errorf("umask %04o produced a key directory at %04o", mask, got)
				}
				if mask == 0o022 {
					want := map[string]os.FileMode{
						layout.FilePrivateKey: 0o600, layout.FilePublicKey: 0o644,
						layout.FileRefreshSecret: 0o600, layout.FileMetadata: 0o600,
					}
					for n, m := range want {
						if got := hostiletest.ModeOf(t, filepath.Join(sb.Keys, n)).Perm(); got != m {
							t.Errorf("%s is %04o, want %04o", n, got, m)
						}
					}
				}
				return
			}

			// A refusal must leave nothing that looks like a set.
			if err := os.Chmod(sb.Keys, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, n := range layout.KeyFileNames() {
				if _, err := os.Lstat(filepath.Join(sb.Keys, n)); err == nil {
					t.Errorf("umask %04o failed but left %s behind", mask, n)
				}
			}
			if left := hostiletest.StagingDirs(t, sb.Keys); len(left) != 0 {
				t.Errorf("umask %04o failed and left staging directories %v", mask, left)
			}
			syscall.Umask(0o022)
			loaded2 := hostiletest.Open(t, sb.Keys, false)
			if loaded2.Err != nil {
				t.Fatalf("a clean run after the hostile umask failed: %v\n%s", loaded2.Err, loaded2.Log.All())
			}
		})
	}
}
