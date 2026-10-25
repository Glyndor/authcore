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
)

// A secret volume refreshes all its files with one atomic step: the ..data link
// is retargeted at a new directory. Starts that overlap the refresh must end
// with a whole set, never the signing key of one set beside the refresh secret
// of the other, which a directory without a recorded binding cannot detect
// afterwards.
func TestHostile_VolumeRefreshDuringStart_neverMixesSets(t *testing.T) {
	requireNonRoot(t)
	sb := newSandbox(t)
	sets := []keySet{newSet(t), newSet(t)}
	stamps := []string{"..stamp_a", "..stamp_b"}
	for i, s := range sets {
		s.writeFiles(t, mustMkdir(t, filepath.Join(sb.outside, stamps[i])))
	}
	mustSymlink(t, stamps[0], filepath.Join(sb.outside, "..data"))
	dir := sb.keysDir(t)
	for _, n := range layout.KeyFileNames() {
		mustSymlink(t, filepath.Join("..data", n), filepath.Join(sb.outside, n))
		mustSymlink(t, filepath.Join(sb.outside, n), filepath.Join(dir, n))
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tmp := filepath.Join(sb.outside, "..data_tmp")
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// One refresh at a time: a volume does not flip back within the
			// microseconds a read takes.
			time.Sleep(300 * time.Microsecond)
			_ = os.Remove(tmp)
			if os.Symlink(stamps[i%2], tmp) == nil {
				_ = os.Rename(tmp, filepath.Join(sb.outside, "..data"))
			}
		}
	}()

	var whole, refusedN int
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		r := open(t, dir, true)
		if r.err != nil {
			refusedN++
			continue
		}
		whole++
		for _, s := range sets {
			if bytes.Equal(r.keys.PrivateKey(), s.priv) && !bytes.Equal(r.keys.RefreshSecret(), s.secret) {
				close(stop)
				wg.Wait()
				t.Fatalf("start %d paired one set's signing key with the other set's refresh secret", whole+refusedN)
			}
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("%d starts loaded a whole set, %d were refused", whole, refusedN)
}
