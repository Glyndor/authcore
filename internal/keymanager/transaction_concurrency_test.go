package keymanager

import (
	"bytes"
	"os"
	"path/filepath"
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

// TestHelperDoesNotDeleteALiveStaging verifies that when goroutine A is
// mid-publish (its private key is linked, its staging directory is still
// present), a second goroutine B that calls New does not remove A's staging
// directory as part of recovering through it.
//
// The fault hook blocks the first caller that reaches "published-private",
// which the test arranges to be A by waiting for A's private key to be
// published before starting B. Every wait is bounded, so a defect here fails
// the run with a message instead of hanging the package.
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

	// Wait until A has linked its private key AND exactly one staging
	// directory is present. The fault hook runs after linkKeys' first
	// linkFile returns, so observing the linked file means A is about to
	// enter (or already inside) the hook. By the time the test proceeds
	// to call B's New, B will see a partial directory and take the
	// recovery path through completeFromStaging, which never calls the
	// "published-private" hook. The previous version of this test waited
	// only for A's staging directory to appear, which happened before A
	// linked the private key; a slow A let B find an empty KeysDir and
	// take the staging path, blocking B in the hook while nothing closed
	// release (A was still between staging and linking). That variant
	// hung the package under load on 2026-09-19, and hung every run when
	// only the first initialiser was delayed 300 ms before its first link.
	deadline := time.Now().Add(2 * time.Second)
	var initial []string
	var privOK bool
	for time.Now().Before(deadline) {
		initial = listStagingDirs(t, dir)
		_, statErr := os.Stat(filepath.Join(dir, filePrivateKey))
		privOK = statErr == nil
		if privOK && len(initial) == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !privOK || len(initial) != 1 {
		t.Fatalf("A's private key did not appear within 2s: staging=%v, privOK=%v", initial, privOK)
	}

	// Run B's New in a goroutine and bound the wait so a defect in the
	// recovery path fails the test instead of hanging the package. Close
	// release on timeout so A can also make progress and surface its own
	// error, which will be more useful than a bare timeout.
	bResult := make(chan error, 1)
	go func() {
		_, err := New(dir, silentLog{})
		bResult <- err
	}()
	var bErr error
	select {
	case bErr = <-bResult:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("B's New did not return within 10s")
	}
	if bErr != nil {
		close(release)
		t.Fatalf("B's New: %v", bErr)
	}
	bSet := readSet(t, dir)

	mid := listStagingDirs(t, dir)
	if len(mid) != 1 || mid[0] != initial[0] {
		t.Fatalf("after B, A's staging dir changed: was %v, now %v", initial, mid)
	}

	close(release)
	var a result
	select {
	case a = <-aResult:
	case <-time.After(10 * time.Second):
		t.Fatal("A's New did not return within 10s after release")
	}
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
