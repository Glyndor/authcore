package keymanager

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Concurrent initialisation tests: many goroutines on one empty directory
// must converge on a single key set, and a process that is mid-publish must
// not have its its staging directory removed by a helper that recovers
// through it.

func TestConcurrentInitAllAgree(t *testing.T) {
	for round := 0; round < 50; round++ {
		dir := t.TempDir()
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 8)
		sets := make([][3][]byte, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-barrier
				km, err := New(dir, silentLog{})
				if err != nil {
					errs[idx] = err
					return
				}
				_ = km
				sets[idx] = readSet(t, dir)
			}(i)
		}
		close(barrier)
		wg.Wait()
		for i, e := range errs {
			if e != nil {
				t.Fatalf("round %d, goroutine %d: %v", round, i, e)
			}
		}
		for i := 1; i < 8; i++ {
			for j := 0; j < 3; j++ {
				if !bytes.Equal(sets[0][j], sets[i][j]) {
					t.Fatalf("round %d: goroutine %d disagrees on key %d", round, i, j)
				}
			}
		}
		if _, err := New(dir, silentLog{}); err != nil {
			t.Fatalf("round %d, later New: %v", round, err)
		}
		later := readSet(t, dir)
		for j := 0; j < 3; j++ {
			if !bytes.Equal(sets[0][j], later[j]) {
				t.Fatalf("round %d: later New disagrees on key %d", round, j)
			}
		}
	}
}

func TestHelperDoesNotDeleteALiveStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	release := make(chan struct{})
	var once sync.Once
	withFaultAt(t, func(p string) error {
		if p == "published-private" {
			once.Do(func() { <-release })
		}
		return nil
	})

	type result struct {
		set [3][]byte
		err error
	}
	aResult := make(chan result, 1)
	go func() {
		km, err := New(dir, silentLog{})
		out := result{}
		if err == nil {
			_ = km
			out.set = readSet(t, dir)
		}
		out.err = err
		aResult <- out
	}()

	deadline := time.Now().Add(2 * time.Second)
	var initial []string
	for time.Now().Before(deadline) {
		initial = listStagingDirs(t, dir)
		if len(initial) == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(initial) != 1 {
		t.Fatalf("A's staging did not appear within 2s: %v", initial)
	}

	_, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("B's New: %v", err)
	}
	bSet := readSet(t, dir)

	mid := listStagingDirs(t, dir)
	if len(mid) != 1 || mid[0] != initial[0] {
		t.Fatalf("after B, A's staging dir changed: was %v, now %v", initial, mid)
	}

	close(release)
	a := <-aResult
	if a.err != nil {
		t.Fatalf("A's New returned %v", a.err)
	}
	for i := 0; i < 3; i++ {
		if !bytes.Equal(a.set[i], bSet[i]) {
			t.Errorf("A and B disagree on key %d", i)
		}
	}

	final := listStagingDirs(t, dir)
	if len(final) != 0 {
		t.Errorf("after A returned, expected no staging dirs, got %v", final)
	}
}
