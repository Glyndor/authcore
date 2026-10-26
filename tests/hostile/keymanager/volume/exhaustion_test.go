//go:build unix

// Package volume attacks the key store with volume-level conditions: huge
// directories, names at the filesystem limit, quota errors and volume refreshes.
package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 11: exhaustion. A directory that is huge, names at the filesystem
// limit, paths past it, and a link count or quota that runs out after the
// private key is published.

// within fails the test when fn takes longer than limit.
func within(t testing.TB, limit time.Duration, what string, fn func()) {
	t.Helper()
	start := time.Now()
	fn()
	if d := time.Since(start); d > limit {
		t.Errorf("%s took %v, limit %v", what, d, limit)
	}
}

func TestHostile_Exhaustion_hugeDirectoryStillLoadsPromptly(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		s := hostiletest.NewSet(t)
		dir := sb.WithSet(t, s)
		for i := range 4000 {
			hostiletest.Put(t, filepath.Join(dir, fmt.Sprintf("unrelated-%05d.txt", i)), nil, 0o600)
		}
		within(t, 5*time.Second, "start in a directory of 4000 entries", func() {
			hostiletest.Loaded(t, hostiletest.Open(t, dir, loadOnly), s)
		})
	})
}

func TestHostile_Exhaustion_manyHalfWrittenStagingDirectoriesDoNotStallRecovery(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.KeysDir(t)
	hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
	for i := range 600 {
		stage := hostiletest.MustMkdir(t, filepath.Join(dir, fmt.Sprintf("%s%016x", layout.StagingPrefix, i)))
		hostiletest.Put(t, filepath.Join(stage, layout.FilePrivateKey), hostiletest.NewSet(t).PrivPEM, 0o600) // another set's key
	}
	mine := hostiletest.MustMkdir(t, filepath.Join(dir, layout.StagingPrefix+"mine"))
	s.WriteFiles(t, mine)

	within(t, 10*time.Second, "recovery among 600 staging directories", func() {
		hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
	})
}

func TestHostile_Exhaustion_namesAtTheFilesystemLimit(t *testing.T) {
	t.Run("staging directory with a 255 byte name is adopted", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		s := hostiletest.NewSet(t)
		dir := sb.KeysDir(t)
		hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
		name := layout.StagingPrefix + strings.Repeat("f", 255-len(layout.StagingPrefix))
		s.WriteFiles(t, hostiletest.MustMkdir(t, filepath.Join(dir, name)))

		r := hostiletest.Open(t, dir, false)

		hostiletest.Loaded(t, r, s)
		hostiletest.AssertNoLeak(t, "log", []hostiletest.KeySet{s}, r.Log.All())
	})
	t.Run("KeysDir whose own name is 255 bytes", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		dir := filepath.Join(sb.Root, strings.Repeat("k", 255))

		r := hostiletest.Open(t, dir, false)

		if r.Err != nil {
			t.Fatalf("generation in a 255 byte directory name: %v", r.Err)
		}
		hostiletest.Loaded(t, hostiletest.Open(t, dir, true), hostiletest.KeySet{Priv: r.Keys.PrivateKey(), Pub: r.Keys.PublicKey(), Secret: r.Keys.RefreshSecret()})
	})
	t.Run("name one byte too long is refused without residue", func(t *testing.T) {
		hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
			sb := hostiletest.NewSandbox(t)
			before := hostiletest.Tree(t, sb.Root)
			hostiletest.Refused(t, hostiletest.Open(t, filepath.Join(sb.Root, strings.Repeat("k", 256)), loadOnly))
			hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
		})
	})
	t.Run("path past PATH_MAX is refused without residue", func(t *testing.T) {
		hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
			sb := hostiletest.NewSandbox(t)
			before := hostiletest.Tree(t, sb.Root)
			deep := sb.Root
			for len(deep) < 5000 {
				deep = filepath.Join(deep, strings.Repeat("d", 200))
			}
			hostiletest.Refused(t, hostiletest.Open(t, deep, loadOnly))
			// MkdirAll may have created the part of the path that fits; nothing
			// else may appear, and load-only creates nothing at all.
			for p, e := range hostiletest.Tree(t, sb.Root) {
				if _, existed := before[p]; !existed && (loadOnly || !strings.HasPrefix(string(e), "dir ")) {
					t.Errorf("%q appeared (%s) after a refused start", p[:min(len(p), 40)], e)
				}
			}
		})
	})
}

// A filesystem that runs out of links or quota after the private key is
// published: every errno an operator can meet, then recovery once space is back.
func TestHostile_Exhaustion_quotaErrorsAfterThePrivateLinkThenRecovery(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOSPC, syscall.EDQUOT, syscall.EMLINK, syscall.EROFS, syscall.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			n := 0
			hostiletest.SetLink(t, func(oldname, newname string) error {
				n++
				if n >= 2 {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errno}
				}
				return os.Link(oldname, newname)
			})
			r := hostiletest.Open(t, dir, false)
			if r.Err == nil {
				t.Fatal("a failing public key link did not stop the start")
			}
			pinned := hostiletest.PublishedPrivate(t, dir)
			if pinned == nil {
				t.Fatal("the private key is not published")
			}
			hostiletest.Refused(t, hostiletest.Open(t, dir, true)) // load-only never completes a partial set

			hostiletest.SetLink(t, os.Link)
			final := hostiletest.Open(t, dir, false)
			if final.Err != nil {
				t.Fatalf("recovery after %v: %v", errno, final.Err)
			}
			if string(hostiletest.PublishedPrivate(t, dir)) != string(pinned) {
				t.Error("recovery replaced the published private key")
			}
		})
	}
}
