//go:build unix

package concurrency

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 10: two faults in a row. concurrency_test.go crashes one start at each
// point and recovers; here the recovery itself is cut short at a second point,
// with a different error, before a third start finally runs clean.

var faultPoints = []string{"staged", "published-private", "published-public", "published-secret", "metadata-written"}

// faultOnce makes the named point fail once with err and every other call pass.
func faultOnce(t testing.TB, point string, err error) {
	t.Helper()
	done := false
	hostiletest.SetFault(t, func(p string) error {
		if p == point && !done {
			done = true
			return err
		}
		return nil
	})
}

func TestHostile_Faults_twoInARowThenACleanStartConverges(t *testing.T) {
	first := fmt.Errorf("first fault: %w", syscall.ENOSPC)
	second := fmt.Errorf("second fault: %w", syscall.EDQUOT)
	for _, p1 := range faultPoints {
		for _, p2 := range faultPoints {
			t.Run(p1+"_then_"+p2, func(t *testing.T) {
				sb := hostiletest.NewSandbox(t)
				dir := sb.KeysDir(t)

				faultOnce(t, p1, first)
				r1 := hostiletest.Open(t, dir, false)
				if r1.Err == nil && p1 != "metadata-written" {
					t.Fatalf("a fault at %s did not stop the start", p1)
				}
				pinned := hostiletest.PublishedPrivate(t, dir)

				faultOnce(t, p2, second)
				hostiletest.Open(t, dir, false) // may fail or succeed; either must leave a recoverable directory
				if pinned != nil {
					if now := hostiletest.PublishedPrivate(t, dir); string(now) != string(pinned) {
						t.Fatal("a second fault replaced the private key published by the first start")
					}
				}

				hostiletest.SetFault(t, func(string) error { return nil })
				final := hostiletest.Open(t, dir, false)
				if final.Err != nil {
					t.Fatalf("a clean start after two faults failed: %v\n%s", final.Err, final.Log.All())
				}
				if pinned != nil && string(hostiletest.PublishedPrivate(t, dir)) != string(pinned) {
					t.Error("the final start regenerated a key that was already published")
				}
				if n := len(hostiletest.StagingDirs(t, dir)); n > 2 {
					t.Errorf("%d staging directories left after two faults", n)
				}

				again := hostiletest.Open(t, dir, true)
				if again.Err != nil || again.Keys.KeyID() != final.Keys.KeyID() {
					t.Errorf("load-only after convergence disagrees: %v", again.Err)
				}
			})
		}
	}
}

// A fault in metadata handling is the last step: the keys are already
// published and complete, so no later start may treat the set as lost.
func TestHostile_Faults_metadataFaultsNeverMakeTheSetLookLost(t *testing.T) {
	for _, point := range []string{"metadata-written", "metadata-before-rename"} {
		t.Run(point, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			faultOnce(t, point, syscall.EIO)
			hostiletest.Open(t, dir, false)
			want := hostiletest.PublishedPrivate(t, dir)
			if want == nil {
				t.Fatal("the private key is not published after a metadata fault")
			}
			hostiletest.SetFault(t, func(string) error { return nil })
			for i := range 3 {
				r := hostiletest.Open(t, dir, i%2 == 1)
				if r.Err != nil {
					t.Fatalf("start %d after a metadata fault: %v", i, r.Err)
				}
			}
			if string(hostiletest.PublishedPrivate(t, dir)) != string(want) {
				t.Error("the private key changed after a metadata fault")
			}
		})
	}
}
