//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
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
	dirs := stagingDirs(t, dir)
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
	requireNonRoot(t)
	for _, point := range []string{"staged", "published-private", "published-public"} {
		for _, change := range midwayChanges {
			t.Run(point+"/"+change.name, func(t *testing.T) {
				sb := newSandbox(t)
				dir := sb.keysDir(t)
				restoreMode(t, dir)
				fired := false
				setFault(t, func(p string) error {
					if p == point && !fired {
						fired = true
						change.apply(t, dir)
					}
					return nil
				})

				r := open(t, dir, false)
				setFault(t, func(string) error { return nil })
				restoreDirTree(dir)
				for _, d := range stagingDirs(t, dir) {
					restoreDirTree(filepath.Join(dir, d))
					for _, n := range layout.KeyFileNames() {
						_ = os.Chmod(filepath.Join(dir, d, n), 0o600)
					}
				}
				pinned := publishedPrivate(t, dir)
				if r.err != nil {
					assertNoLeak(t, "error", nil, r.err.Error())
				}

				final := open(t, dir, false)
				if final.err != nil {
					t.Fatalf("a start after the modes were restored failed: %v\n%s", final.err, final.log.all())
				}
				if pinned != nil && string(publishedPrivate(t, dir)) != string(pinned) {
					t.Error("the key published during the mode change was replaced")
				}
				for _, n := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
					if fi, err := os.Stat(filepath.Join(dir, n)); err != nil || fi.Mode().Perm()&0o077 != 0 {
						t.Errorf("%s ended with mode %v (err %v), want owner only", n, fi.Mode().Perm(), err)
					}
				}
				if again := open(t, dir, true); again.err != nil || again.keys.KeyID() != final.keys.KeyID() {
					t.Errorf("load-only after recovery disagrees: %v", again.err)
				}
			})
		}
	}
}

// A key file made unreadable after a successful start must not be loaded from
// a stale copy: the next start refuses, and the file is not rewritten.
func TestHostile_Midway_aKeyFileLockedBetweenStartsIsRefusedNotRegenerated(t *testing.T) {
	requireNonRoot(t)
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.withSet(t, s)
			loaded(t, open(t, dir, false), s)
			path := filepath.Join(dir, name)
			chmodOrFail(t, path, 0)
			restoreMode(t, path)

			bothModes(t, func(t *testing.T, loadOnly bool) {
				refused(t, open(t, dir, loadOnly), s)
			})

			chmodOrFail(t, path, 0o600)
			loaded(t, open(t, dir, false), s)
		})
	}
}
