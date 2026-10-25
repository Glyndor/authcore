//go:build unix

package hostile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
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
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		s := newSet(t)
		dir := sb.withSet(t, s)
		for i := range 4000 {
			put(t, filepath.Join(dir, fmt.Sprintf("unrelated-%05d.txt", i)), nil, 0o600)
		}
		within(t, 5*time.Second, "start in a directory of 4000 entries", func() {
			loaded(t, open(t, dir, loadOnly), s)
		})
	})
}

func TestHostile_Exhaustion_manyHalfWrittenStagingDirectoriesDoNotStallRecovery(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.keysDir(t)
	put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
	for i := range 600 {
		stage := mustMkdir(t, filepath.Join(dir, fmt.Sprintf("%s%016x", layout.StagingPrefix, i)))
		put(t, filepath.Join(stage, layout.FilePrivateKey), newSet(t).privPEM, 0o600) // another set's key
	}
	mine := mustMkdir(t, filepath.Join(dir, layout.StagingPrefix+"mine"))
	s.writeFiles(t, mine)

	within(t, 10*time.Second, "recovery among 600 staging directories", func() {
		loaded(t, open(t, dir, false), s)
	})
}

func TestHostile_Exhaustion_namesAtTheFilesystemLimit(t *testing.T) {
	t.Run("staging directory with a 255 byte name is adopted", func(t *testing.T) {
		sb := newSandbox(t)
		s := newSet(t)
		dir := sb.keysDir(t)
		put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
		name := layout.StagingPrefix + strings.Repeat("f", 255-len(layout.StagingPrefix))
		s.writeFiles(t, mustMkdir(t, filepath.Join(dir, name)))

		r := open(t, dir, false)

		loaded(t, r, s)
		assertNoLeak(t, "log", []keySet{s}, r.log.all())
	})
	t.Run("KeysDir whose own name is 255 bytes", func(t *testing.T) {
		sb := newSandbox(t)
		dir := filepath.Join(sb.root, strings.Repeat("k", 255))

		r := open(t, dir, false)

		if r.err != nil {
			t.Fatalf("generation in a 255 byte directory name: %v", r.err)
		}
		loaded(t, open(t, dir, true), keySet{priv: r.keys.PrivateKey(), pub: r.keys.PublicKey(), secret: r.keys.RefreshSecret()})
	})
	t.Run("name one byte too long is refused without residue", func(t *testing.T) {
		bothModes(t, func(t *testing.T, loadOnly bool) {
			sb := newSandbox(t)
			before := tree(t, sb.root)
			refused(t, open(t, filepath.Join(sb.root, strings.Repeat("k", 256)), loadOnly))
			assertSame(t, "sandbox", before, tree(t, sb.root))
		})
	})
	t.Run("path past PATH_MAX is refused without residue", func(t *testing.T) {
		bothModes(t, func(t *testing.T, loadOnly bool) {
			sb := newSandbox(t)
			before := tree(t, sb.root)
			deep := sb.root
			for len(deep) < 5000 {
				deep = filepath.Join(deep, strings.Repeat("d", 200))
			}
			refused(t, open(t, deep, loadOnly))
			// MkdirAll may have created the part of the path that fits; nothing
			// else may appear, and load-only creates nothing at all.
			for p, e := range tree(t, sb.root) {
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
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			n := 0
			setLink(t, func(oldname, newname string) error {
				n++
				if n >= 2 {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errno}
				}
				return os.Link(oldname, newname)
			})
			r := open(t, dir, false)
			if r.err == nil {
				t.Fatal("a failing public key link did not stop the start")
			}
			pinned := publishedPrivate(t, dir)
			if pinned == nil {
				t.Fatal("the private key is not published")
			}
			refused(t, open(t, dir, true)) // load-only never completes a partial set

			setLink(t, os.Link)
			final := open(t, dir, false)
			if final.err != nil {
				t.Fatalf("recovery after %v: %v", errno, final.err)
			}
			if string(publishedPrivate(t, dir)) != string(pinned) {
				t.Error("recovery replaced the published private key")
			}
		})
	}
}
