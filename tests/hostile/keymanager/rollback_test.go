//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
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
	dst := mustMkdir(t, filepath.Join(t.TempDir(), "backup"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			fi, _ := e.Info()
			put(t, filepath.Join(dst, e.Name()), read(t, filepath.Join(dir, e.Name())), fi.Mode().Perm())
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
		put(t, path, read(t, filepath.Join(backup, e.Name())), fi.Mode().Perm())
	}
}

func TestHostile_Rollback_aWholeOlderDirectoryLoadsAsExactlyThatSet(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		older, newer := newSet(t), newSet(t)
		dir := sb.withSet(t, older)
		loaded(t, open(t, dir, false), older)
		backup := snapshotDir(t, dir)

		// Rotate forward on purpose: replace the set and drop the old marker, as
		// the documented rotation does.
		newer.writeFiles(t, dir)
		if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
			t.Fatal(err)
		}
		loaded(t, open(t, dir, false), newer)

		restoreFrom(t, backup, dir)
		before := tree(t, dir)

		loaded(t, open(t, dir, loadOnly), older)

		assertSame(t, "KeysDir after loading the rolled back set", before, tree(t, dir))
	})
}

func TestHostile_Rollback_swappingBetweenTwoValidDirectoriesNeverBlendsThem(t *testing.T) {
	sb := newSandbox(t)
	a, b := newSet(t), newSet(t)
	dir := sb.withSet(t, a)
	loaded(t, open(t, dir, false), a)
	backupA := snapshotDir(t, dir)

	b.writeFiles(t, dir)
	_ = os.Remove(filepath.Join(dir, layout.FileMetadata))
	loaded(t, open(t, dir, false), b)
	backupB := snapshotDir(t, dir)

	for i := range 6 {
		want, backup := a, backupA
		if i%2 == 1 {
			want, backup = b, backupB
		}
		restoreFrom(t, backup, dir)
		loaded(t, open(t, dir, i%3 == 0), want)
	}
}
