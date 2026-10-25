//go:build unix

package hostile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// Class 5: concurrent initialisers, crashes at every point of the publish
// transaction and recovery racing recovery.

// raceN runs fn(i) for i in [0,n) released at the same instant.
func raceN(n int, fn func(i int) result) []result {
	out := make([]result, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return out
}

// sameSet asserts every successful result holds one and the same key set and
// returns its key id.
func sameSet(t *testing.T, results []result) string {
	t.Helper()
	var id string
	var first result
	for i, r := range results {
		if r.err != nil {
			continue
		}
		if id == "" {
			id, first = r.keys.KeyID(), r
			continue
		}
		if r.keys.KeyID() != id || string(r.keys.PrivateKey()) != string(first.keys.PrivateKey()) ||
			string(r.keys.RefreshSecret()) != string(first.keys.RefreshSecret()) {
			t.Fatalf("initialiser %d holds key id %s, another holds %s: a mixed or regenerated set", i, r.keys.KeyID(), id)
		}
	}
	return id
}

// keyIDOfPrivateFile derives the key id from a private key file on disk.
func keyIDOfPrivateFile(t *testing.T, path string) string {
	t.Helper()
	priv, err := pemcodec.DecodeEd25519PrivatePEM(read(t, path), path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return hex.EncodeToString(h[:8])
}

// assertCleanFinalState checks KeysDir holds exactly a complete set and the
// two bookkeeping files, with no staging directory left.
func assertCleanFinalState(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	want := []string{layout.FileGitignore, layout.FilePrivateKey, layout.FilePublicKey, layout.FileRefreshSecret, layout.FileMetadata}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("KeysDir holds %v, want %v", got, want)
	}
}

func TestHostile_Concurrency_manyGoroutinesOnAnEmptyDirectoryAgreeOnOneSet(t *testing.T) {
	for round := range 6 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := newSandbox(t)
			results := raceN(16, func(int) result { return open(t, sb.keys, false) })

			for i, r := range results {
				if r.err != nil {
					t.Fatalf("initialiser %d failed: %v\n%s", i, r.err, r.log.all())
				}
			}
			id := sameSet(t, results)
			if id != keyIDOfPrivateFile(t, filepath.Join(sb.keys, layout.FilePrivateKey)) {
				t.Error("the keys the initialisers hold are not the keys on disk")
			}
			assertCleanFinalState(t, sb.keys)
			loaded2 := open(t, sb.keys, true)
			if loaded2.err != nil || loaded2.keys.KeyID() != id {
				t.Errorf("a later load-only start disagrees: %v", loaded2.err)
			}
		})
	}
}

func TestHostile_Concurrency_loadersRacingGeneratorsSeeOneSetOrAnError(t *testing.T) {
	for round := range 6 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := newSandbox(t)
			mustMkdir(t, sb.keys)
			results := raceN(24, func(i int) result { return open(t, sb.keys, i%3 == 0) })

			for i, r := range results {
				if i%3 != 0 && r.err != nil {
					t.Fatalf("writable initialiser %d failed: %v", i, r.err)
				}
			}
			id := sameSet(t, results)
			if id == "" {
				t.Fatal("nobody ended up with a set")
			}
			assertCleanFinalState(t, sb.keys)
		})
	}
}

func TestHostile_Concurrency_manyGoroutinesOnAnExistingSetAllLoadIt(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	results := raceN(32, func(i int) result { return open(t, dir, i%2 == 0) })
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("loader %d failed: %v", i, r.err)
		}
		loaded(t, r, s)
	}
}

// Crashes: the seam aborts the publish at a named point without cleanup.

var crashPoints = []string{"staged", "published-private", "published-public", "published-secret", "metadata-written"}

func TestHostile_Concurrency_crashAtEveryPointThenRecover(t *testing.T) {
	for _, point := range crashPoints {
		t.Run(point, func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			crashAt(t, point)

			crashed := open(t, dir, false)
			if crashed.err == nil {
				t.Fatalf("the crash at %q did not abort the run", point)
			}
			setFault(t, func(string) error { return nil })
			privPath := filepath.Join(dir, layout.FilePrivateKey)
			publishedBefore := ""
			if _, err := os.Stat(privPath); err == nil {
				publishedBefore = keyIDOfPrivateFile(t, privPath)
			}

			r := open(t, dir, false)
			if r.err != nil {
				t.Fatalf("recovery after a crash at %q failed: %v\n%s", point, r.err, r.log.all())
			}
			id := r.keys.KeyID()
			if publishedBefore != "" && id != publishedBefore {
				t.Errorf("a key published before the crash (%s) was replaced by %s", publishedBefore, id)
			}
			if got := keyIDOfPrivateFile(t, privPath); got != id {
				t.Errorf("the loaded key %s is not the key on disk %s", id, got)
			}
			again := open(t, dir, true)
			if again.err != nil || again.keys.KeyID() != id {
				t.Errorf("the recovered set does not load again identically: %v", again.err)
			}
			for _, n := range layout.KeyFileNames() {
				if m := modeOf(t, filepath.Join(dir, n)).Perm(); m&0o022 != 0 {
					t.Errorf("%s ended up at %04o", n, m)
				}
			}
		})
	}
}

func TestHostile_Concurrency_diskFaultAfterEachLinkThenRecover(t *testing.T) {
	for allowed := range 3 {
		t.Run(fmt.Sprintf("after%dLinks", allowed), func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			n := 0
			setLink(t, func(oldname, newname string) error {
				n++
				if n > allowed {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EIO}
				}
				return os.Link(oldname, newname)
			})
			refused(t, open(t, dir, false))
			setLink(t, os.Link)
			privPath := filepath.Join(dir, layout.FilePrivateKey)
			publishedBefore := ""
			if _, err := os.Stat(privPath); err == nil {
				publishedBefore = keyIDOfPrivateFile(t, privPath)
			}

			r := open(t, dir, false)
			if r.err != nil {
				t.Fatalf("recovery failed: %v", r.err)
			}
			if publishedBefore != "" && r.keys.KeyID() != publishedBefore {
				t.Errorf("recovery replaced the published key %s with %s", publishedBefore, r.keys.KeyID())
			}
		})
	}
}

func TestHostile_Concurrency_crashInsideRecoveryThenRecoverAgain(t *testing.T) {
	for allowed := range 2 {
		t.Run(fmt.Sprintf("after%dLinks", allowed), func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			crashAt(t, "published-private")
			refused(t, open(t, dir, false))
			setFault(t, func(string) error { return nil })
			want := keyIDOfPrivateFile(t, filepath.Join(dir, layout.FilePrivateKey))

			n := 0
			setLink(t, func(oldname, newname string) error {
				n++
				if n > allowed {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EIO}
				}
				return os.Link(oldname, newname)
			})
			refused(t, open(t, dir, false))
			setLink(t, os.Link)

			r := open(t, dir, false)
			if r.err != nil {
				t.Fatalf("the second recovery failed: %v", r.err)
			}
			if r.keys.KeyID() != want {
				t.Errorf("key id %s after a double recovery, want %s", r.keys.KeyID(), want)
			}
		})
	}
}

func TestHostile_Concurrency_manyRecoverersCompleteTheSameSet(t *testing.T) {
	for _, point := range []string{"published-private", "published-public"} {
		for round := range 4 {
			t.Run(fmt.Sprintf("%s/round%d", point, round), func(t *testing.T) {
				sb := newSandbox(t)
				dir := sb.keysDir(t)
				crashAt(t, point)
				refused(t, open(t, dir, false))
				setFault(t, func(string) error { return nil })
				want := keyIDOfPrivateFile(t, filepath.Join(dir, layout.FilePrivateKey))

				results := raceN(16, func(i int) result { return open(t, dir, i%4 == 0) })

				for i, r := range results {
					if i%4 != 0 && r.err != nil {
						t.Fatalf("recoverer %d failed: %v", i, r.err)
					}
				}
				if id := sameSet(t, results); id != want {
					t.Fatalf("recovered key id %q, want %q", id, want)
				}
			})
		}
	}
}

// Multiple processes: this test binary re-executes itself as the initialisers.

const childEnv = "AUTHCORE_HOSTILE_CHILD"

// TestHostile_Concurrency_childProcess is the body of one initialiser
// process. It only does anything when the parent test started it.
func TestHostile_Concurrency_childProcess(t *testing.T) {
	spec := os.Getenv(childEnv)
	if spec == "" {
		t.Skip("helper process of TestHostile_Concurrency_processesAgreeOnOneSet; nothing to do when run directly")
	}
	parts := strings.Split(spec, "|")
	dir, mode, gate, ready := parts[0], parts[1], parts[2], parts[3]
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gate never opened")
		}
		time.Sleep(time.Millisecond)
	}
	r := open(t, dir, mode == "load")
	if r.err != nil {
		fmt.Printf("RESULT err %s\n", strings.ReplaceAll(r.err.Error(), "\n", " "))
		return
	}
	fmt.Printf("RESULT ok %s %x\n", r.keys.KeyID(), r.keys.RefreshSecret())
}

func TestHostile_Concurrency_processesAgreeOnOneSet(t *testing.T) {
	const writers, loaders = 8, 4
	for round := range 3 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := newSandbox(t)
			gate := filepath.Join(sb.root, "gate")
			type child struct {
				cmd  *exec.Cmd
				out  *strings.Builder
				load bool
			}
			var children []child
			for i := range writers + loaders {
				mode := "new"
				if i >= writers {
					mode = "load"
				}
				ready := filepath.Join(sb.root, fmt.Sprintf("ready-%d", i))
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHostile_Concurrency_childProcess$", "-test.count=1")
				cmd.Env = append(os.Environ(), childEnv+"="+strings.Join([]string{sb.keys, mode, gate, ready}, "|"))
				out := &strings.Builder{}
				cmd.Stdout, cmd.Stderr = out, out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				children = append(children, child{cmd, out, mode == "load"})
			}
			// Release them together once every one is waiting at the gate.
			for i := range children {
				ready := filepath.Join(sb.root, fmt.Sprintf("ready-%d", i))
				for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Millisecond) {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("child %d never became ready", i)
					}
				}
			}
			put(t, gate, nil, 0o600)

			ids := map[string]bool{}
			for i, c := range children {
				if err := c.cmd.Wait(); err != nil {
					t.Fatalf("child %d crashed or failed: %v\n%s", i, err, c.out)
				}
				var result string
				for _, line := range strings.Split(c.out.String(), "\n") {
					if strings.HasPrefix(line, "RESULT ") {
						result = line
					}
				}
				switch {
				case result == "":
					t.Fatalf("child %d printed no result:\n%s", i, c.out)
				case strings.HasPrefix(result, "RESULT err"):
					if !c.load {
						t.Fatalf("writable child %d failed: %s", i, result)
					}
				default:
					ids[strings.TrimPrefix(result, "RESULT ok ")] = true
				}
			}
			if len(ids) != 1 {
				t.Fatalf("processes ended with %d different key sets: %v", len(ids), ids)
			}
			assertCleanFinalState(t, sb.keys)
		})
	}
}
