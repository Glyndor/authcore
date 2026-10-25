//go:build unix

package hostile

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// refreshVolume lays out two key sets the way a mounted secret volume does:
// the key files in KeysDir link to files outside it, which link to
// ..data/<name>, and ..data points at one of two stamped directories. It
// returns KeysDir, the sets and a function that retargets ..data at set i with
// one atomic rename, as a volume refresh does.
func refreshVolume(t *testing.T) (dir string, sets []keySet, point func(i int)) {
	t.Helper()
	sb := newSandbox(t)
	sets = []keySet{newSet(t), newSet(t)}
	stamps := []string{"..stamp_a", "..stamp_b"}
	for i, s := range sets {
		s.writeFiles(t, mustMkdir(t, filepath.Join(sb.outside, stamps[i])))
	}
	mustSymlink(t, stamps[0], filepath.Join(sb.outside, "..data"))
	dir = sb.keysDir(t)
	for _, n := range layout.KeyFileNames() {
		mustSymlink(t, filepath.Join("..data", n), filepath.Join(sb.outside, n))
		mustSymlink(t, filepath.Join(sb.outside, n), filepath.Join(dir, n))
	}
	tmp := filepath.Join(sb.outside, "..data_tmp")
	point = func(i int) {
		_ = os.Remove(tmp)
		if err := os.Symlink(stamps[i], tmp); err == nil {
			_ = os.Rename(tmp, filepath.Join(sb.outside, "..data"))
		}
	}
	return dir, sets, point
}

// mixed reports whether the keys pair the signing key of one set with the
// refresh secret of another.
func mixed(r result, sets []keySet) bool {
	for _, s := range sets {
		if bytes.Equal(r.keys.PrivateKey(), s.priv) && !bytes.Equal(r.keys.RefreshSecret(), s.secret) {
			return true
		}
	}
	return false
}

// A volume that goes from set A to set B and back to A while a start is
// reading leaves every path exactly as the start found it, yet the files were
// read from different versions. The seam fires between the reads, so the
// sequence is the same on every run: after the public key is read the volume
// moves to B (the refresh secret is then read from B) and when the last file
// is read it moves back to A. The start must repeat the read and end with set
// A whole.
func TestHostile_VolumeRefreshAToBToA_neverMixesSets(t *testing.T) {
	requireNonRoot(t)
	bothModes(t, func(t *testing.T, loadOnly bool) {
		dir, sets, point := refreshVolume(t)
		attempts := 0
		prev := seams.AfterKeyRead
		t.Cleanup(func() { seams.AfterKeyRead = prev })
		seams.AfterKeyRead = func(attempt, file int) {
			attempts = attempt + 1
			if attempt != 0 {
				return
			}
			switch file {
			case 1:
				point(1)
			case 2:
				point(0)
			}
		}

		r := open(t, dir, loadOnly)
		if r.err != nil {
			t.Fatalf("start: %v", r.err)
		}
		if mixed(r, sets) {
			t.Fatal("the start paired one set's signing key with the other set's refresh secret")
		}
		if !bytes.Equal(r.keys.PrivateKey(), sets[0].priv) || !bytes.Equal(r.keys.RefreshSecret(), sets[0].secret) {
			t.Error("the start did not end with set A whole")
		}
		if attempts < 2 {
			t.Errorf("the start read %d time(s); the change should have forced a repeat", attempts)
		}
	})
}

// A secret volume refreshes all its files with one atomic step: the ..data link
// is retargeted at a new directory. Starts that overlap the refresh must end
// with a whole set, never the signing key of one set beside the refresh secret
// of the other, which a directory without a recorded binding cannot detect
// afterwards.
//
// This variant lets the timing decide, so it is only as strong as the
// scheduler makes it; the deterministic test above is the one that pins the
// behaviour. A refresh lands every few milliseconds, which is far faster than
// a real volume and still slow enough that a loaded runner cannot fit three of
// them inside the microseconds a start spends between its first and last look
// at the files.
func TestHostile_VolumeRefreshDuringStart_neverMixesSets(t *testing.T) {
	requireNonRoot(t)
	dir, sets, point := refreshVolume(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			point(i % 2)
		}
	}()
	finish := func() { close(stop); wg.Wait() }

	var whole, refusedN int
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		r := open(t, dir, true)
		if r.err != nil {
			refusedN++
			continue
		}
		whole++
		if mixed(r, sets) {
			finish()
			t.Fatalf("start %d paired one set's signing key with the other set's refresh secret", whole+refusedN)
		}
	}
	finish()
	t.Logf("%d starts loaded a whole set, %d were refused", whole, refusedN)
}
