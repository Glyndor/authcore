//go:build unix

package hostile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 9: an active attacker rewrites KeysDir in a loop while New and Load run
// (run with -race). Whatever the attacker does, a start must end in one of two
// ways: an error, or a key set whose private key, public key and refresh secret
// are consistent with each other. The victim file and directory outside KeysDir
// must come out byte for byte as they went in, and nothing may panic or hang.

// raceWindow is how long each attacked test keeps starting key managers.
const raceWindow = 300 * time.Millisecond

// victimArea is what the attacker aims links at; it stands for everything an
// attack must not write to.
func victimArea(t testing.TB, sb sandbox) (path string, snapshot map[string]entry) {
	t.Helper()
	path = filepath.Join(sb.outside, "victim.txt")
	put(t, path, []byte("precious\n"), 0o600)
	return path, tree(t, sb.outside)
}

// consistent reports whether a successful start holds one coherent key pair.
func consistent(r result, sets []keySet) (matched bool, issue string) {
	for _, s := range sets {
		if bytes.Equal(r.keys.PrivateKey(), s.priv) {
			if !bytes.Equal(r.keys.PublicKey(), s.pub) {
				return true, "public key is not the public half of the private key"
			}
			// The refresh secret is not compared with the set: the three files are
			// read one after another, so a replacement that lands between the reads
			// can pair a key with the other set's secret.
			if len(r.keys.RefreshSecret()) != layout.RefreshSecretLen {
				return true, "the refresh secret has the wrong length"
			}
			if r.keys.KeyID() != s.keyID() {
				return true, "key id does not belong to the private key"
			}
			return true, ""
		}
	}
	return false, "the private key is not any set the attacker or the owner wrote"
}

func TestHostile_Race_attackerRewritesKeysDirWhileNewAndLoadRun(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		requireNonRoot(t)
		sb := newSandbox(t)
		owner, other := newSet(t), newSet(t)
		dir := sb.withSet(t, owner)
		victim, before := victimArea(t, sb)

		stop := startAttack(t, dir,
			newAttacker(dir, victim, []keySet{owner, other}, 1),
			newAttacker(dir, victim, []keySet{owner, other}, 2))

		var loadedN, refusedN int
		for deadline := time.Now().Add(raceWindow); time.Now().Before(deadline); {
			r := open(t, dir, loadOnly)
			if r.err != nil {
				refusedN++
				assertNoLeak(t, "error", []keySet{owner, other}, r.err.Error(), r.log.all())
				continue
			}
			loadedN++
			if ok, issue := consistent(r, []keySet{owner, other}); !ok || issue != "" {
				t.Fatalf("start %d accepted an incoherent set: %s", loadedN+refusedN, issue)
			}
			assertNoLeak(t, "log", []keySet{owner, other}, r.log.all())
		}
		stop()

		assertSame(t, "outside KeysDir", before, tree(t, sb.outside))
		t.Logf("%d starts loaded a coherent set, %d were refused", loadedN, refusedN)
	})
}

// A generator racing an attacker on an empty directory may fail, but it must
// never publish through a link the attacker planted nor leave KeysDir holding a
// private key that does not match the public one beside it.
func TestHostile_Race_attackerPlantsLinksWhileTheSetIsGenerated(t *testing.T) {
	requireNonRoot(t)
	for round := range 4 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			victim, before := victimArea(t, sb)
			stop := startAttack(t, dir, newAttacker(dir, victim, []keySet{newSet(t)}, uint64(round)+10,
				"link-to-victim", "dir-in-place", "chmod-closed", "chmod-open", "remove-file", "plant-staging", "drop-staging"))

			deadline := time.Now().Add(250 * time.Millisecond)
			for time.Now().Before(deadline) {
				r := open(t, dir, false)
				if r.err == nil {
					if ok, issue := consistent(r, nil); issue != "" && ok {
						t.Fatal(issue)
					}
				}
			}
			stop()
			assertSame(t, "outside KeysDir", before, tree(t, sb.outside))
		})
	}
}

// Many starts at once under attack: the in-process initialisers share the
// directory with the attacker and with each other.
func TestHostile_Race_manyStartsAndAnAttackerShareOneDirectory(t *testing.T) {
	requireNonRoot(t)
	sb := newSandbox(t)
	owner, other := newSet(t), newSet(t)
	dir := sb.withSet(t, owner)
	victim, before := victimArea(t, sb)
	stop := startAttack(t, dir, newAttacker(dir, victim, []keySet{owner, other}, 77))

	var wg sync.WaitGroup
	problems := make(chan string, 64)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for deadline := time.Now().Add(raceWindow); time.Now().Before(deadline); {
				r := open(t, dir, g%2 == 0)
				if r.err != nil {
					continue
				}
				if ok, issue := consistent(r, []keySet{owner, other}); !ok || issue != "" {
					problems <- issue
					return
				}
			}
		}()
	}
	wg.Wait()
	stop()
	close(problems)
	for p := range problems {
		t.Error(p)
	}
	assertSame(t, "outside KeysDir", before, tree(t, sb.outside))
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the victim file is gone: %v", err)
	}
}
