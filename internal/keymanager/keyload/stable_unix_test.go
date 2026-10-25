//go:build unix

package keyload

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// swapLink points the symlink at link to target, atomically.
func swapLink(t *testing.T, link, target string) {
	t.Helper()
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
}

// volume lays out two sets the way a mounted secret volume does: the key
// names in dir are links to ..data/<name>, and ..data points at one of two
// stamped directories. It returns both sets and a function that retargets
// ..data.
func volume(t *testing.T) (dir string, sets [2]keyloadtest.KeySet, point func(i int)) {
	t.Helper()
	root := t.TempDir()
	stamps := [2]string{"..stamp_a", "..stamp_b"}
	for i, st := range stamps {
		d := filepath.Join(root, st)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		sets[i] = keyloadtest.WriteSet(t, d)
	}
	data := filepath.Join(root, "..data")
	if err := os.Symlink(stamps[0], data); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(root, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range layout.KeyFileNames() {
		if err := os.Symlink(filepath.Join(data, n), filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	return dir, sets, func(i int) { swapLink(t, data, stamps[i]) }
}

// A volume that goes from set A to set B and back while the files are read
// leaves the paths exactly as they were found, yet the secret was read from B.
// Looking at the paths before and after cannot see it; the descriptors can.
func TestFiles_aVolumeThatGoesAToBToAMidReadNeverYieldsAMixedSet(t *testing.T) {
	dir, sets, point := volume(t)
	attempts := 0
	hooks(t, func(attempt, file int) {
		attempts = attempt + 1
		if attempt != 0 {
			return
		}
		switch file {
		case 1:
			point(1) // A -> B: the secret is read from B
		case lastFile:
			point(0) // B -> A: the paths look untouched again
		}
	})

	priv, _, secret, err := Files(dir, keyloadtest.SilentLog{})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if attempts != 2 {
		t.Errorf("read %d times, want a repeat (2)", attempts)
	}
	if !priv.Equal(sets[0].Priv) || string(secret) != string(sets[0].Secret) {
		t.Fatal("the signing key and the refresh secret come from different sets")
	}
}

func TestFiles_aVolumeThatNeverSettlesIsRefusedNotMixed(t *testing.T) {
	dir, _, point := volume(t)
	hooks(t, func(_, file int) {
		switch file {
		case 1:
			point(1)
		case lastFile:
			point(0)
		}
	})

	_, _, _, err := Files(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "changed while they were being read") {
		t.Fatalf("Files = %v, want the changed-while-reading refusal", err)
	}
}

func TestFiles_aPipeInPlaceOfAKeyFileDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	fifo := filepath.Join(dir, layout.FileRefreshSecret)
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	hooks(t, nil)

	done := make(chan error, 1)
	go func() { _, _, _, err := Files(dir, keyloadtest.SilentLog{}); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Files = %v, want the not-a-regular-file refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Files hangs on a pipe")
	}
}
