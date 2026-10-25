//go:build unix

package hostile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 10: two faults in a row. concurrency_test.go crashes one start at each
// point and recovers; here the recovery itself is cut short at a second point,
// with a different error, before a third start finally runs clean.

var faultPoints = []string{"staged", "published-private", "published-public", "published-secret", "metadata-written"}

// faultOnce makes the named point fail once with err and every other call pass.
func faultOnce(t testing.TB, point string, err error) {
	t.Helper()
	done := false
	setFault(t, func(p string) error {
		if p == point && !done {
			done = true
			return err
		}
		return nil
	})
}

func publishedPrivate(t testing.TB, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHostile_Faults_twoInARowThenACleanStartConverges(t *testing.T) {
	first := fmt.Errorf("first fault: %w", syscall.ENOSPC)
	second := fmt.Errorf("second fault: %w", syscall.EDQUOT)
	for _, p1 := range faultPoints {
		for _, p2 := range faultPoints {
			t.Run(p1+"_then_"+p2, func(t *testing.T) {
				sb := newSandbox(t)
				dir := sb.keysDir(t)

				faultOnce(t, p1, first)
				r1 := open(t, dir, false)
				if r1.err == nil && p1 != "metadata-written" {
					t.Fatalf("a fault at %s did not stop the start", p1)
				}
				pinned := publishedPrivate(t, dir)

				faultOnce(t, p2, second)
				open(t, dir, false) // may fail or succeed; either must leave a recoverable directory
				if pinned != nil {
					if now := publishedPrivate(t, dir); string(now) != string(pinned) {
						t.Fatal("a second fault replaced the private key published by the first start")
					}
				}

				setFault(t, func(string) error { return nil })
				final := open(t, dir, false)
				if final.err != nil {
					t.Fatalf("a clean start after two faults failed: %v\n%s", final.err, final.log.all())
				}
				if pinned != nil && string(publishedPrivate(t, dir)) != string(pinned) {
					t.Error("the final start regenerated a key that was already published")
				}
				if n := len(stagingDirs(t, dir)); n > 2 {
					t.Errorf("%d staging directories left after two faults", n)
				}

				again := open(t, dir, true)
				if again.err != nil || again.keys.KeyID() != final.keys.KeyID() {
					t.Errorf("load-only after convergence disagrees: %v", again.err)
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
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			faultOnce(t, point, syscall.EIO)
			open(t, dir, false)
			want := publishedPrivate(t, dir)
			if want == nil {
				t.Fatal("the private key is not published after a metadata fault")
			}
			setFault(t, func(string) error { return nil })
			for i := range 3 {
				r := open(t, dir, i%2 == 1)
				if r.err != nil {
					t.Fatalf("start %d after a metadata fault: %v", i, r.err)
				}
			}
			if string(publishedPrivate(t, dir)) != string(want) {
				t.Error("the private key changed after a metadata fault")
			}
		})
	}
}
