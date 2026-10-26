//go:build unix

package concurrency

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Crashes: the seam aborts the publish at a named point without cleanup.

var crashPoints = []string{"staged", "published-private", "published-public", "published-secret", "metadata-written"}

func TestHostile_Concurrency_crashAtEveryPointThenRecover(t *testing.T) {
	for _, point := range crashPoints {
		t.Run(point, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			hostiletest.CrashAt(t, point)

			crashed := hostiletest.Open(t, dir, false)
			if crashed.Err == nil {
				t.Fatalf("the crash at %q did not abort the run", point)
			}
			hostiletest.SetFault(t, func(string) error { return nil })
			privPath := filepath.Join(dir, layout.FilePrivateKey)
			publishedBefore := ""
			if _, err := os.Stat(privPath); err == nil {
				publishedBefore = keyIDOfPrivateFile(t, privPath)
			}

			r := hostiletest.Open(t, dir, false)
			if r.Err != nil {
				t.Fatalf("recovery after a crash at %q failed: %v\n%s", point, r.Err, r.Log.All())
			}
			id := r.Keys.KeyID()
			if publishedBefore != "" && id != publishedBefore {
				t.Errorf("a key published before the crash (%s) was replaced by %s", publishedBefore, id)
			}
			if got := keyIDOfPrivateFile(t, privPath); got != id {
				t.Errorf("the loaded key %s is not the key on disk %s", id, got)
			}
			again := hostiletest.Open(t, dir, true)
			if again.Err != nil || again.Keys.KeyID() != id {
				t.Errorf("the recovered set does not load again identically: %v", again.Err)
			}
			for _, n := range layout.KeyFileNames() {
				if m := hostiletest.ModeOf(t, filepath.Join(dir, n)).Perm(); m&0o022 != 0 {
					t.Errorf("%s ended up at %04o", n, m)
				}
			}
		})
	}
}

func TestHostile_Concurrency_diskFaultAfterEachLinkThenRecover(t *testing.T) {
	for allowed := range 3 {
		t.Run(fmt.Sprintf("after%dLinks", allowed), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			n := 0
			hostiletest.SetLink(t, func(oldname, newname string) error {
				n++
				if n > allowed {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EIO}
				}
				return os.Link(oldname, newname)
			})
			hostiletest.Refused(t, hostiletest.Open(t, dir, false))
			hostiletest.SetLink(t, os.Link)
			privPath := filepath.Join(dir, layout.FilePrivateKey)
			publishedBefore := ""
			if _, err := os.Stat(privPath); err == nil {
				publishedBefore = keyIDOfPrivateFile(t, privPath)
			}

			r := hostiletest.Open(t, dir, false)
			if r.Err != nil {
				t.Fatalf("recovery failed: %v", r.Err)
			}
			if publishedBefore != "" && r.Keys.KeyID() != publishedBefore {
				t.Errorf("recovery replaced the published key %s with %s", publishedBefore, r.Keys.KeyID())
			}
		})
	}
}

func TestHostile_Concurrency_crashInsideRecoveryThenRecoverAgain(t *testing.T) {
	for allowed := range 2 {
		t.Run(fmt.Sprintf("after%dLinks", allowed), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			hostiletest.CrashAt(t, "published-private")
			hostiletest.Refused(t, hostiletest.Open(t, dir, false))
			hostiletest.SetFault(t, func(string) error { return nil })
			want := keyIDOfPrivateFile(t, filepath.Join(dir, layout.FilePrivateKey))

			n := 0
			hostiletest.SetLink(t, func(oldname, newname string) error {
				n++
				if n > allowed {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EIO}
				}
				return os.Link(oldname, newname)
			})
			hostiletest.Refused(t, hostiletest.Open(t, dir, false))
			hostiletest.SetLink(t, os.Link)

			r := hostiletest.Open(t, dir, false)
			if r.Err != nil {
				t.Fatalf("the second recovery failed: %v", r.Err)
			}
			if r.Keys.KeyID() != want {
				t.Errorf("key id %s after a double recovery, want %s", r.Keys.KeyID(), want)
			}
		})
	}
}

func TestHostile_Concurrency_manyRecoverersCompleteTheSameSet(t *testing.T) {
	for _, point := range []string{"published-private", "published-public"} {
		for round := range 4 {
			t.Run(fmt.Sprintf("%s/round%d", point, round), func(t *testing.T) {
				sb := hostiletest.NewSandbox(t)
				dir := sb.KeysDir(t)
				hostiletest.CrashAt(t, point)
				hostiletest.Refused(t, hostiletest.Open(t, dir, false))
				hostiletest.SetFault(t, func(string) error { return nil })
				want := keyIDOfPrivateFile(t, filepath.Join(dir, layout.FilePrivateKey))

				results := raceN(16, func(i int) hostiletest.Result { return hostiletest.Open(t, dir, i%4 == 0) })

				for i, r := range results {
					if i%4 != 0 && r.Err != nil {
						t.Fatalf("recoverer %d failed: %v", i, r.Err)
					}
				}
				if id := sameSet(t, results); id != want {
					t.Fatalf("recovered key id %q, want %q", id, want)
				}
			})
		}
	}
}
