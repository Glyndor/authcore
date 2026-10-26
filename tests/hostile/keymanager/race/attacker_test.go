//go:build unix

package race

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// attacker is an active adversary with write access to KeysDir. It mutates the
// directory in a loop while the code under test runs, using only operations a
// local user can perform: atomic renames over a key file, replacing a key file
// with a link or a directory, changing modes, and planting staging directories.
// Every operation error is ignored, because the attacker losing a race with the
// victim is not what the tests measure.
type attacker struct {
	dir     string
	victim  string // a path outside KeysDir the attacker points links at
	sets    []hostiletest.KeySet
	actions []string
	rng     *rand.Rand
	ops     int
}

// linkMu serialises planting a link and chmodding, so two attackers cannot
// chmod through a link the other has just planted: that would be the test's own
// doing, not the code under test.
var linkMu sync.Mutex

// attackerActions is the full repertoire, used when a test does not narrow it.
var attackerActions = []string{
	"restore", "restore", "restore", "swap-file", "swap-set", "link-to-victim", "dir-in-place", "chmod-closed",
	"chmod-open", "plant-staging", "drop-staging", "garble-metadata", "remove-file",
}

func newAttacker(dir, victim string, sets []hostiletest.KeySet, seed uint64, actions ...string) *attacker {
	if len(actions) == 0 {
		actions = attackerActions
	}
	return &attacker{dir: dir, victim: victim, sets: sets, actions: actions, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b9))}
}

// run attacks until stop is closed and returns when the loop has ended.
func (a *attacker) run(stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		a.step()
		a.ops++
		if a.ops%16 == 0 {
			time.Sleep(50 * time.Microsecond)
		}
	}
}

func (a *attacker) pick() hostiletest.KeySet { return a.sets[a.rng.IntN(len(a.sets))] }

func (a *attacker) name() string {
	names := layout.KeyFileNames()
	return names[a.rng.IntN(len(names))]
}

// atomicPut writes data beside path and renames it over path.
func (a *attacker) atomicPut(path string, data []byte, mode os.FileMode) {
	tmp := filepath.Join(a.dir, ".atk-tmp-"+filepath.Base(path))
	if os.WriteFile(tmp, data, mode) != nil {
		return
	}
	_ = os.Chmod(tmp, mode)
	_ = os.Rename(tmp, path)
}

func fileOfSet(s hostiletest.KeySet, name string) ([]byte, os.FileMode) {
	switch name {
	case layout.FilePrivateKey:
		return s.PrivPEM, 0o600
	case layout.FilePublicKey:
		return s.PubPEM, 0o644
	default:
		return s.SecretHex, 0o600
	}
}

// chmod changes the mode of path unless it is a link: a chmod would follow
// the link the attacker planted and change the victim, which is the test
// harness acting, not the code under test.
func (a *attacker) chmod(path string, mode os.FileMode) {
	linkMu.Lock()
	defer linkMu.Unlock()
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		_ = os.Chmod(path, mode)
	}
}

func (a *attacker) step() {
	name := a.name()
	path := filepath.Join(a.dir, name)
	switch a.actions[a.rng.IntN(len(a.actions))] {
	case "restore":
		for _, n := range layout.KeyFileNames() {
			_ = os.Remove(filepath.Join(a.dir, n))
			data, mode := fileOfSet(a.sets[0], n)
			a.atomicPut(filepath.Join(a.dir, n), data, mode)
		}
	case "swap-file":
		data, mode := fileOfSet(a.pick(), name)
		a.atomicPut(path, data, mode)
	case "swap-set":
		s := a.pick()
		for _, n := range layout.KeyFileNames() {
			data, mode := fileOfSet(s, n)
			a.atomicPut(filepath.Join(a.dir, n), data, mode)
		}
	case "link-to-victim":
		linkMu.Lock()
		_ = os.Remove(path)
		_ = os.Symlink(a.victim, path)
		linkMu.Unlock()
	case "dir-in-place":
		_ = os.Remove(path)
		_ = os.Mkdir(path, 0o700)
	case "chmod-closed":
		a.chmod(path, 0)
	case "chmod-open":
		a.chmod(path, 0o600)
	case "plant-staging":
		stage := filepath.Join(a.dir, layout.StagingPrefix+"atk")
		if os.Mkdir(stage, 0o700) == nil {
			s := a.pick()
			writeFilesQuiet(s, stage)
		}
	case "drop-staging":
		_ = os.RemoveAll(filepath.Join(a.dir, layout.StagingPrefix+"atk"))
	case "garble-metadata":
		meta := filepath.Join(a.dir, layout.FileMetadata)
		if a.rng.IntN(2) == 0 {
			a.atomicPut(meta, []byte(`{"format":1,"key_id":"`+a.pick().KeyID()+`"}`), 0o600)
		} else {
			a.atomicPut(meta, []byte("{"), 0o600)
		}
	case "remove-file":
		_ = os.Remove(path)
	}
}

// writeFilesQuiet is writeFiles without a testing.TB, for use off the test
// goroutine, ignoring errors.
func writeFilesQuiet(s hostiletest.KeySet, dir string) {
	for _, n := range layout.KeyFileNames() {
		data, mode := fileOfSet(s, n)
		_ = os.WriteFile(filepath.Join(dir, n), data, mode)
	}
}

// startAttack launches attackers and returns a function that stops them and
// restores any mode that would stop TempDir cleanup.
func startAttack(t testing.TB, dir string, atks ...*attacker) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, a := range atks {
		wg.Add(1)
		go a.run(done, &wg)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			close(done)
			wg.Wait()
			hostiletest.RestoreDirTree(dir)
		})
	}
	t.Cleanup(stop)
	return stop
}
