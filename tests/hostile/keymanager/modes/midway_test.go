//go:build unix

package modes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 13: the environment changes underneath a start that is already running.
// A fault hook stands in for the other actor: at the named point of the publish
// transaction it changes a mode, then lets the start carry on.

type midwayChange struct {
	name  string
	apply func(t testing.TB, dir string)
}

func staging(t testing.TB, dir string) string {
	t.Helper()
	dirs := hostiletest.StagingDirs(t, dir)
	if len(dirs) == 0 {
		t.Fatal("no staging directory at the fault point")
	}
	return filepath.Join(dir, dirs[0])
}

var midwayChanges = []midwayChange{
	{"KeysDir becomes read-only", func(t testing.TB, dir string) { chmodOrFail(t, dir, 0o500) }},
	{"KeysDir loses write and read", func(t testing.TB, dir string) { chmodOrFail(t, dir, 0o100) }},
	{"staging directory is locked", func(t testing.TB, dir string) { chmodOrFail(t, staging(t, dir), 0) }},
	{"staged private key is locked", func(t testing.TB, dir string) {
		chmodOrFail(t, filepath.Join(staging(t, dir), layout.FilePrivateKey), 0)
	}},
	{"KeysDir opened to everyone", func(t testing.TB, dir string) { chmodOrFail(t, dir, 0o777) }},
}

func chmodOrFail(t testing.TB, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestHostile_Midway_aModeChangeDuringPublishNeverMixesOrLeaks(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, point := range []string{"staged", "published-private", "published-public"} {
		for _, change := range midwayChanges {
			t.Run(point+"/"+change.name, func(t *testing.T) {
				sb := hostiletest.NewSandbox(t)
				dir := sb.KeysDir(t)
				hostiletest.RestoreMode(t, dir)
				fired := false
				hostiletest.SetFault(t, func(p string) error {
					if p == point && !fired {
						fired = true
						change.apply(t, dir)
					}
					return nil
				})

				r := hostiletest.Open(t, dir, false)
				hostiletest.SetFault(t, func(string) error { return nil })
				hostiletest.RestoreDirTree(dir)
				for _, d := range hostiletest.StagingDirs(t, dir) {
					hostiletest.RestoreDirTree(filepath.Join(dir, d))
					for _, n := range layout.KeyFileNames() {
						_ = os.Chmod(filepath.Join(dir, d, n), 0o600)
					}
				}
				pinned := hostiletest.PublishedPrivate(t, dir)
				if r.Err != nil {
					hostiletest.AssertNoLeak(t, "error", nil, r.Err.Error())
				}

				final := hostiletest.Open(t, dir, false)
				if final.Err != nil {
					t.Fatalf("a start after the modes were restored failed: %v\n%s", final.Err, final.Log.All())
				}
				if pinned != nil && string(hostiletest.PublishedPrivate(t, dir)) != string(pinned) {
					t.Error("the key published during the mode change was replaced")
				}
				for _, n := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
					if fi, err := os.Stat(filepath.Join(dir, n)); err != nil || fi.Mode().Perm()&0o077 != 0 {
						t.Errorf("%s ended with mode %v (err %v), want owner only", n, fi.Mode().Perm(), err)
					}
				}
				if again := hostiletest.Open(t, dir, true); again.Err != nil || again.Keys.KeyID() != final.Keys.KeyID() {
					t.Errorf("load-only after recovery disagrees: %v", again.Err)
				}
			})
		}
	}
}

// A key file made unreadable after a successful start must not be loaded from
// a stale copy: the next start refuses, and the file is not rewritten.
func TestHostile_Midway_aKeyFileLockedBetweenStartsIsRefusedNotRegenerated(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.WithSet(t, s)
			hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
			path := filepath.Join(dir, name)
			chmodOrFail(t, path, 0)
			hostiletest.RestoreMode(t, path)

			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
			})

			chmodOrFail(t, path, 0o600)
			hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
		})
	}
}
