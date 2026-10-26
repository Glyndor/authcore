//go:build unix

package metadata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 14: rollback to an older, internally valid key set.
//
// Restoring every file of KeysDir from an older backup produces a directory
// that is indistinguishable from one that was never rotated: the keys, the
// secret and metadata.json all agree with each other. The start cannot know it
// is older, so it loads it. These tests pin what is guaranteed in that case:
// the set that loads is exactly the one on disk (never a blend of old and new),
// nothing on disk changes, and the quiet acceptance is the documented behaviour
// rather than an accident. Rolling back only part of the directory is a
// different case and is refused (see the metadata tests).

// snapshotDir copies every regular file of dir into a fresh directory.
func snapshotDir(t testing.TB, dir string) string {
	t.Helper()
	dst := hostiletest.MustMkdir(t, filepath.Join(t.TempDir(), "backup"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			fi, _ := e.Info()
			hostiletest.Put(t, filepath.Join(dst, e.Name()), hostiletest.Read(t, filepath.Join(dir, e.Name())), fi.Mode().Perm())
		}
	}
	return dst
}

// restoreDir replaces the regular files of dir with those of backup.
func restoreFrom(t testing.TB, backup, dir string) {
	t.Helper()
	entries, err := os.ReadDir(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		fi, _ := e.Info()
		path := filepath.Join(dir, e.Name())
		_ = os.Remove(path)
		hostiletest.Put(t, path, hostiletest.Read(t, filepath.Join(backup, e.Name())), fi.Mode().Perm())
	}
}

func TestHostile_Rollback_aWholeOlderDirectoryLoadsAsExactlyThatSet(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		older, newer := hostiletest.NewSet(t), hostiletest.NewSet(t)
		dir := sb.WithSet(t, older)
		hostiletest.Loaded(t, hostiletest.Open(t, dir, false), older)
		backup := snapshotDir(t, dir)

		// Rotate forward on purpose: replace the set and drop the old marker, as
		// the documented rotation does.
		newer.WriteFiles(t, dir)
		if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
			t.Fatal(err)
		}
		hostiletest.Loaded(t, hostiletest.Open(t, dir, false), newer)

		restoreFrom(t, backup, dir)
		before := hostiletest.Tree(t, dir)

		hostiletest.Loaded(t, hostiletest.Open(t, dir, loadOnly), older)

		hostiletest.AssertSame(t, "KeysDir after loading the rolled back set", before, hostiletest.Tree(t, dir))
	})
}

func TestHostile_Rollback_swappingBetweenTwoValidDirectoriesNeverBlendsThem(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	a, b := hostiletest.NewSet(t), hostiletest.NewSet(t)
	dir := sb.WithSet(t, a)
	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), a)
	backupA := snapshotDir(t, dir)

	b.WriteFiles(t, dir)
	_ = os.Remove(filepath.Join(dir, layout.FileMetadata))
	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), b)
	backupB := snapshotDir(t, dir)

	for i := range 6 {
		want, backup := a, backupA
		if i%2 == 1 {
			want, backup = b, backupB
		}
		restoreFrom(t, backup, dir)
		hostiletest.Loaded(t, hostiletest.Open(t, dir, i%3 == 0), want)
	}
}
