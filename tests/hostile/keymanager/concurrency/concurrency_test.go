//go:build unix

// Package concurrency starts the key manager from many goroutines and
// processes, crashes it at every point of the publish and checks recovery.
package concurrency

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 5: concurrent initialisers, crashes at every point of the publish
// transaction and recovery racing recovery.

// raceN runs fn(i) for i in [0,n) released at the same instant.
func raceN(n int, fn func(i int) hostiletest.Result) []hostiletest.Result {
	out := make([]hostiletest.Result, n)
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
func sameSet(t *testing.T, results []hostiletest.Result) string {
	t.Helper()
	var id string
	var first hostiletest.Result
	for i, r := range results {
		if r.Err != nil {
			continue
		}
		if id == "" {
			id, first = r.Keys.KeyID(), r
			continue
		}
		if r.Keys.KeyID() != id || string(r.Keys.PrivateKey()) != string(first.Keys.PrivateKey()) ||
			string(r.Keys.RefreshSecret()) != string(first.Keys.RefreshSecret()) {
			t.Fatalf("initialiser %d holds key id %s, another holds %s: a mixed or regenerated set", i, r.Keys.KeyID(), id)
		}
	}
	return id
}

// keyIDOfPrivateFile derives the key id from a private key file on disk.
func keyIDOfPrivateFile(t *testing.T, path string) string {
	t.Helper()
	priv, err := pemcodec.DecodeEd25519PrivatePEM(hostiletest.Read(t, path), path)
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
			sb := hostiletest.NewSandbox(t)
			results := raceN(16, func(int) hostiletest.Result { return hostiletest.Open(t, sb.Keys, false) })

			for i, r := range results {
				if r.Err != nil {
					t.Fatalf("initialiser %d failed: %v\n%s", i, r.Err, r.Log.All())
				}
			}
			id := sameSet(t, results)
			if id != keyIDOfPrivateFile(t, filepath.Join(sb.Keys, layout.FilePrivateKey)) {
				t.Error("the keys the initialisers hold are not the keys on disk")
			}
			assertCleanFinalState(t, sb.Keys)
			loaded2 := hostiletest.Open(t, sb.Keys, true)
			if loaded2.Err != nil || loaded2.Keys.KeyID() != id {
				t.Errorf("a later load-only start disagrees: %v", loaded2.Err)
			}
		})
	}
}

func TestHostile_Concurrency_loadersRacingGeneratorsSeeOneSetOrAnError(t *testing.T) {
	for round := range 6 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			hostiletest.MustMkdir(t, sb.Keys)
			results := raceN(24, func(i int) hostiletest.Result { return hostiletest.Open(t, sb.Keys, i%3 == 0) })

			for i, r := range results {
				if i%3 != 0 && r.Err != nil {
					t.Fatalf("writable initialiser %d failed: %v", i, r.Err)
				}
			}
			id := sameSet(t, results)
			if id == "" {
				t.Fatal("nobody ended up with a set")
			}
			assertCleanFinalState(t, sb.Keys)
		})
	}
}

func TestHostile_Concurrency_manyGoroutinesOnAnExistingSetAllLoadIt(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	results := raceN(32, func(i int) hostiletest.Result { return hostiletest.Open(t, dir, i%2 == 0) })
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("loader %d failed: %v", i, r.Err)
		}
		hostiletest.Loaded(t, r, s)
	}
}
