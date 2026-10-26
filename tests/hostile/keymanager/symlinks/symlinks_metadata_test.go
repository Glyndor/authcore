//go:build unix

package symlinks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

func TestHostile_Symlinks_metadataLinkIsReplacedNeverWrittenThrough(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	external := filepath.Join(sb.Outside, "meta.json")
	hostiletest.Put(t, external, []byte(`{"format":1,"created":"2020-01-01T00:00:00Z","key_id":"0000000000000000"}`+"\n"), 0o644)
	hostiletest.MustSymlink(t, external, filepath.Join(dir, layout.FileMetadata))
	before := hostiletest.Tree(t, sb.Outside)

	r := hostiletest.Open(t, dir, false)
	hostiletest.Loaded(t, r, s)

	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	fi, err := os.Lstat(filepath.Join(dir, layout.FileMetadata))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("metadata.json should now be a regular file inside KeysDir, got %v (%v)", fi, err)
	}
	if !strings.Contains(string(hostiletest.Read(t, filepath.Join(dir, layout.FileMetadata))), s.KeyID()) {
		t.Error("the refreshed metadata.json does not record the loaded key id")
	}
	if !r.Log.Has("signing key changed") {
		t.Error("a metadata key id that disagrees with the keys was rewritten without a log line")
	}
}

func TestHostile_Symlinks_danglingMetadataLinkCreatesNothingOutside(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "never-created.json"), filepath.Join(dir, layout.FileMetadata))
	before := hostiletest.Tree(t, sb.Outside)

	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)

	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
}

func TestHostile_Symlinks_metadataLinkToNonRegularTargetIsRefused(t *testing.T) {
	for _, target := range []string{"/dev/zero", "/dev/null", "/dev/urandom", "/tmp", "/"} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				if _, err := os.Stat(target); err != nil {
					t.Skipf("%s does not exist here", target)
				}
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				hostiletest.MustSymlink(t, target, filepath.Join(dir, layout.FileMetadata))
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
			})
		})
	}
}

func TestHostile_Symlinks_gitignoreLinkIsNeverWrittenThrough(t *testing.T) {
	t.Run("dangling", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "gitignore"), filepath.Join(dir, layout.FileGitignore))
		before := hostiletest.Tree(t, sb.Outside)

		r := hostiletest.Open(t, dir, false)
		if r.Err != nil {
			t.Fatalf("a hostile .gitignore must not stop key generation: %v", r.Err)
		}

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
		if !r.Log.Has(".gitignore") {
			t.Error("the refused .gitignore write was not reported")
		}
	})
	t.Run("existing target", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		target := filepath.Join(sb.Outside, "gitignore")
		hostiletest.Put(t, target, []byte("keep me\n"), 0o644)
		hostiletest.MustSymlink(t, target, filepath.Join(dir, layout.FileGitignore))
		before := hostiletest.Tree(t, sb.Outside)

		if r := hostiletest.Open(t, dir, false); r.Err != nil {
			t.Fatal(r.Err)
		}
		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_Symlinks_stagingLinkIsNotAdopted(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.KeysDir(t)
	hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
	// The planted directory holds a complete set whose private key matches the
	// published one, which is what makes a real staging directory adoptable.
	planted := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "planted"))
	s.WriteFiles(t, planted)
	hostiletest.MustSymlink(t, planted, filepath.Join(dir, layout.StagingPrefix+"evil"))
	before := hostiletest.Tree(t, sb.Outside)

	hostiletest.Refused(t, hostiletest.Open(t, dir, false), s)

	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s was linked in from a symlinked staging directory", n)
		}
	}
}

func TestHostile_Symlinks_linkInsideStagingIsNotAdopted(t *testing.T) {
	for _, linked := range layout.KeyFileNames() {
		t.Run(linked, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.KeysDir(t)
			hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
			staging := hostiletest.MustMkdir(t, filepath.Join(dir, layout.StagingPrefix+"half"))
			s.WriteFiles(t, staging)
			// Swap one staged file for a link to an identical file elsewhere.
			external := filepath.Join(sb.Outside, "copy")
			hostiletest.Put(t, external, hostiletest.Read(t, filepath.Join(staging, linked)), 0o600)
			if err := os.Remove(filepath.Join(staging, linked)); err != nil {
				t.Fatal(err)
			}
			hostiletest.MustSymlink(t, external, filepath.Join(staging, linked))

			hostiletest.Refused(t, hostiletest.Open(t, dir, false), s)
			if _, err := os.Lstat(filepath.Join(dir, layout.FileRefreshSecret)); err == nil {
				t.Error("recovery completed the set from a staging directory that contains a symlink")
			}
		})
	}
}

func TestHostile_Symlinks_parentDirectoryLinkKeepsKeysInTheResolvedDirectory(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	real := hostiletest.MustMkdir(t, filepath.Join(sb.Root, "real-parent"))
	hostiletest.MustSymlink(t, real, filepath.Join(sb.Root, "link-parent"))
	dir := filepath.Join(sb.Root, "link-parent", "keys")

	r := hostiletest.Open(t, dir, false)
	if r.Err != nil {
		t.Fatal(r.Err)
	}

	for _, n := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(real, "keys", n)); err != nil {
			t.Errorf("%s missing in the resolved directory: %v", n, err)
		}
	}
	entries, _ := os.ReadDir(sb.Root)
	if len(entries) != 3 { // outside, real-parent, link-parent
		t.Errorf("unexpected entries beside the sandbox: %v", entries)
	}
}

// TOCTOU: the symlink appears after the preflight looked and before the link.

func TestHostile_Symlinks_swapAfterPreflightDoesNotReachTheVictim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing bool
	}{{"victim absent", false}, {"victim present", true}} {
		t.Run(tc.name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			victim := filepath.Join(sb.Outside, "victim")
			if tc.existing {
				hostiletest.Put(t, victim, []byte("precious\n"), 0o600)
			}
			before := hostiletest.Tree(t, sb.Outside)
			hostiletest.SetFault(t, func(point string) error {
				if point == "staged" {
					return os.Symlink(victim, filepath.Join(dir, layout.FilePrivateKey))
				}
				return nil
			})

			r := hostiletest.Open(t, dir, false)

			hostiletest.Refused(t, r)
			if !strings.Contains(r.Err.Error(), "never writes key material through one") {
				t.Errorf("the refusal does not name the symlink: %v", r.Err)
			}
			hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
			if _, err := os.Lstat(filepath.Join(dir, layout.FilePublicKey)); err == nil {
				t.Error("the public key was published after the private link was refused")
			}
		})
	}
}

func TestHostile_Symlinks_swapMidPublishLeavesVictimAndRecovers(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	dir := sb.KeysDir(t)
	victim := filepath.Join(sb.Outside, "victim-public")
	before := hostiletest.Tree(t, sb.Outside)
	hostiletest.SetFault(t, func(point string) error {
		if point == "published-private" {
			return os.Symlink(victim, filepath.Join(dir, layout.FilePublicKey))
		}
		return nil
	})
	hostiletest.Refused(t, hostiletest.Open(t, dir, false))
	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))

	hostiletest.SetFault(t, func(string) error { return nil })
	// The dangling link is still there: recovery must refuse it too, not write
	// through it, and the staging directory must survive as recovery material.
	hostiletest.Refused(t, hostiletest.Open(t, dir, false))
	hostiletest.AssertSame(t, "outside after retry", before, hostiletest.Tree(t, sb.Outside))
	if len(hostiletest.StagingDirs(t, dir)) == 0 {
		t.Fatal("the staging directory was deleted while the set was incomplete")
	}

	// Once the operator removes the link the same set is completed, not regenerated.
	priv := hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey))
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	r := hostiletest.Open(t, dir, false)
	if r.Err != nil {
		t.Fatalf("recovery after removing the link: %v\n%s", r.Err, r.Log.All())
	}
	if string(hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey))) != string(priv) {
		t.Error("the private key changed during recovery")
	}
}
