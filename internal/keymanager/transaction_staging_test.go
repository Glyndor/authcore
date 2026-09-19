package keymanager

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Staging and wait tests: an interrupted publish must leave the disk in a
// shape a fresh process can finish, and a bounded wait must time out with a
// message that names what is on disk.

func TestInterruptedInitRestarts(t *testing.T) {
	points := []string{
		"staged",
		"published-private",
		"published-public",
		"published-secret",
		"metadata-written",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			sentinel := fmt.Errorf("crash at %s", point)
			withFaultAt(t, func(p string) error {
				if p == point {
					return sentinel
				}
				return nil
			})

			_, err := New(dir, silentLog{})
			if !errors.Is(err, sentinel) {
				t.Fatalf("first New at %q: want sentinel, got %v", point, err)
			}
			crashSet := readPublishedSet(t, dir)

			withFaultAt(t, nil)
			log2 := &recordingLog{}
			if _, err := New(dir, log2); err != nil {
				t.Fatalf("second New after %q: %v", point, err)
			}
			secondSet := readSet(t, dir)

			log3 := &recordingLog{}
			if _, err := New(dir, log3); err != nil {
				t.Fatalf("third New: %v", err)
			}
			thirdSet := readSet(t, dir)

			for i := range secondSet {
				if !bytes.Equal(secondSet[i], thirdSet[i]) {
					t.Errorf("key %d changed between second and third New at %q", i, point)
				}
			}
			if point != "staged" {
				for i, b := range crashSet {
					if b == nil {
						continue
					}
					if !bytes.Equal(b, thirdSet[i]) {
						t.Errorf("key %d changed across crash+restart at %q", i, point)
					}
				}
			}

			staging := listStagingDirs(t, dir)
			if len(staging) > 1 {
				t.Errorf("at %q, expected at most one staging dir, got %v", point, staging)
			}
			if len(staging) == 1 {
				if !log2.warnContains(staging[0]) && !log3.warnContains(staging[0]) {
					t.Errorf("at %q, expected a Warn naming %q", point, staging[0])
				}
			}
		})
	}
}

func TestWaitExpiresWithAccurateMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wait timing depends on POSIX file semantics")
	}
	dir := t.TempDir()

	prevWait, prevPoll := publishWait, publishPoll
	publishWait = 50 * time.Millisecond
	publishPoll = 5 * time.Millisecond
	t.Cleanup(func() {
		publishWait, publishPoll = prevWait, prevPoll
	})

	start := time.Now()
	err := waitForSet(dir, silentLog{})
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("wait exceeded 1s on an empty dir: %v", elapsed)
	}
	if err == nil {
		t.Fatal("waitForSet returned nil on an empty dir")
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("error must say 'did not finish', got: %v", err)
	}
	if strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must not mention symlinks, got: %v", err)
	}
}
