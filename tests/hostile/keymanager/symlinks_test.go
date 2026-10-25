//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 1: symlinks in every position.

func TestHostile_Symlinks_keyFileToExternalVictim(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		victim := filepath.Join(sb.outside, "victim.txt")
		put(t, victim, []byte("not a key\n"), 0o644)
		mustSymlink(t, victim, filepath.Join(dir, layout.FilePrivateKey))
		before := tree(t, sb.outside)

		refused(t, open(t, dir, loadOnly))

		assertSame(t, "outside", before, tree(t, sb.outside))
		for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
			if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
				t.Errorf("%s was created next to a symlinked private key", n)
			}
		}
	})
}

func TestHostile_Symlinks_danglingKeyFilesAimedOutside(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		for _, n := range layout.KeyFileNames() {
			mustSymlink(t, filepath.Join(sb.outside, "planted-"+n), filepath.Join(dir, n))
		}
		before := tree(t, sb.outside)

		refused(t, open(t, dir, loadOnly))

		// A write through the link would have created the planted file.
		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_Symlinks_oneDanglingKeyAmongRealOnes(t *testing.T) {
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.withSet(t, s)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(sb.outside, "planted"), filepath.Join(dir, name))
			before := tree(t, sb.outside)

			refused(t, open(t, dir, false), s)

			assertSame(t, "outside", before, tree(t, sb.outside))
		})
	}
}

func TestHostile_Symlinks_systemFilesAsKeys(t *testing.T) {
	targets := []string{"/etc/passwd", "/etc/hostname", "/etc/os-release", "/etc/ssl/certs/ca-certificates.crt"}
	var present []string
	for _, p := range targets {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	if len(present) == 0 {
		t.Skip("none of the probe files in /etc exists on this host")
	}
	for _, target := range present {
		for _, name := range layout.KeyFileNames() {
			t.Run(strings.ReplaceAll(target, "/", "_")+"_as_"+name, func(t *testing.T) {
				sb := newSandbox(t)
				s := newSet(t)
				dir := sb.withSet(t, s)
				link := filepath.Join(dir, name)
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, target, link)

				r := open(t, dir, true)
				refused(t, r, s)

				// The refusal may name the path, never the content of the file.
				first, _, _ := strings.Cut(string(read(t, target)), "\n")
				if len(first) > 8 && strings.Contains(r.err.Error()+r.log.all(), first) {
					t.Errorf("the content of %s reached the error or the log: %q", target, first)
				}
			})
		}
	}
}

func TestHostile_Symlinks_loopInKeyFile(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		a, b := filepath.Join(dir, "loop-a"), filepath.Join(dir, "loop-b")
		mustSymlink(t, b, a)
		mustSymlink(t, a, b)
		mustSymlink(t, a, filepath.Join(dir, layout.FilePrivateKey))

		refused(t, open(t, dir, loadOnly))
	})
}

func TestHostile_Symlinks_selfLinkAsMetadata(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		s := newSet(t)
		dir := sb.withSet(t, s)
		mustSymlink(t, filepath.Join(dir, layout.FileMetadata), filepath.Join(dir, layout.FileMetadata))
		refused(t, open(t, dir, loadOnly), s)
	})
}

func TestHostile_Symlinks_kubernetesProjectionLoadsAndLoadOnlyWritesNothing(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	// A Secret volume projects each file as a link through ..data to a
	// timestamped directory. Reads must follow, which is the documented reason
	// the read path does not refuse links.
	stamp := mustMkdir(t, filepath.Join(sb.outside, "..2026_10_25"))
	s.writeFiles(t, stamp)
	mustSymlink(t, "..2026_10_25", filepath.Join(sb.outside, "..data"))
	dir := sb.keysDir(t)
	for _, n := range layout.KeyFileNames() {
		mustSymlink(t, filepath.Join("..data", n), filepath.Join(sb.outside, n))
		mustSymlink(t, filepath.Join(sb.outside, n), filepath.Join(dir, n))
	}
	beforeOutside, beforeDir := tree(t, sb.outside), tree(t, dir)

	loaded(t, open(t, dir, true), s)
	assertSame(t, "outside after load-only", beforeOutside, tree(t, sb.outside))
	assertSame(t, "KeysDir after load-only", beforeDir, tree(t, dir))

	loaded(t, open(t, dir, false), s)
	assertSame(t, "outside after New", beforeOutside, tree(t, sb.outside))
	for _, n := range layout.KeyFileNames() {
		if fi, _ := os.Lstat(filepath.Join(dir, n)); fi == nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("New replaced the projected link %s", n)
		}
	}
}

func TestHostile_Symlinks_pairSplitAcrossTwoSetsIsRefused(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		a, b := newSet(t), newSet(t)
		dirA := mustMkdir(t, filepath.Join(sb.outside, "a"))
		dirB := mustMkdir(t, filepath.Join(sb.outside, "b"))
		a.writeFiles(t, dirA)
		b.writeFiles(t, dirB)
		dir := sb.keysDir(t)
		mustSymlink(t, filepath.Join(dirA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
		mustSymlink(t, filepath.Join(dirB, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))
		mustSymlink(t, filepath.Join(dirA, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))

		refused(t, open(t, dir, loadOnly), a, b)
	})
}

func TestHostile_Symlinks_metadataLinkIsReplacedNeverWrittenThrough(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	external := filepath.Join(sb.outside, "meta.json")
	put(t, external, []byte(`{"format":1,"created":"2020-01-01T00:00:00Z","key_id":"0000000000000000"}`+"\n"), 0o644)
	mustSymlink(t, external, filepath.Join(dir, layout.FileMetadata))
	before := tree(t, sb.outside)

	r := open(t, dir, false)
	loaded(t, r, s)

	assertSame(t, "outside", before, tree(t, sb.outside))
	fi, err := os.Lstat(filepath.Join(dir, layout.FileMetadata))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("metadata.json should now be a regular file inside KeysDir, got %v (%v)", fi, err)
	}
	if !strings.Contains(string(read(t, filepath.Join(dir, layout.FileMetadata))), s.keyID()) {
		t.Error("the refreshed metadata.json does not record the loaded key id")
	}
	if !r.log.has("signing key changed") {
		t.Error("a metadata key id that disagrees with the keys was rewritten without a log line")
	}
}

func TestHostile_Symlinks_danglingMetadataLinkCreatesNothingOutside(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	mustSymlink(t, filepath.Join(sb.outside, "never-created.json"), filepath.Join(dir, layout.FileMetadata))
	before := tree(t, sb.outside)

	loaded(t, open(t, dir, false), s)

	assertSame(t, "outside", before, tree(t, sb.outside))
}

func TestHostile_Symlinks_metadataLinkToNonRegularTargetIsRefused(t *testing.T) {
	for _, target := range []string{"/dev/zero", "/dev/null", "/dev/urandom", "/tmp", "/"} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				if _, err := os.Stat(target); err != nil {
					t.Skipf("%s does not exist here", target)
				}
				sb := newSandbox(t)
				s := newSet(t)
				dir := sb.withSet(t, s)
				mustSymlink(t, target, filepath.Join(dir, layout.FileMetadata))
				refused(t, open(t, dir, loadOnly), s)
			})
		})
	}
}

func TestHostile_Symlinks_gitignoreLinkIsNeverWrittenThrough(t *testing.T) {
	t.Run("dangling", func(t *testing.T) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		mustSymlink(t, filepath.Join(sb.outside, "gitignore"), filepath.Join(dir, layout.FileGitignore))
		before := tree(t, sb.outside)

		r := open(t, dir, false)
		if r.err != nil {
			t.Fatalf("a hostile .gitignore must not stop key generation: %v", r.err)
		}

		assertSame(t, "outside", before, tree(t, sb.outside))
		if !r.log.has(".gitignore") {
			t.Error("the refused .gitignore write was not reported")
		}
	})
	t.Run("existing target", func(t *testing.T) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		target := filepath.Join(sb.outside, "gitignore")
		put(t, target, []byte("keep me\n"), 0o644)
		mustSymlink(t, target, filepath.Join(dir, layout.FileGitignore))
		before := tree(t, sb.outside)

		if r := open(t, dir, false); r.err != nil {
			t.Fatal(r.err)
		}
		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_Symlinks_stagingLinkIsNotAdopted(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.keysDir(t)
	put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
	// The planted directory holds a complete set whose private key matches the
	// published one, which is what makes a real staging directory adoptable.
	planted := mustMkdir(t, filepath.Join(sb.outside, "planted"))
	s.writeFiles(t, planted)
	mustSymlink(t, planted, filepath.Join(dir, layout.StagingPrefix+"evil"))
	before := tree(t, sb.outside)

	refused(t, open(t, dir, false), s)

	assertSame(t, "outside", before, tree(t, sb.outside))
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s was linked in from a symlinked staging directory", n)
		}
	}
}

func TestHostile_Symlinks_linkInsideStagingIsNotAdopted(t *testing.T) {
	for _, linked := range layout.KeyFileNames() {
		t.Run(linked, func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.keysDir(t)
			put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
			staging := mustMkdir(t, filepath.Join(dir, layout.StagingPrefix+"half"))
			s.writeFiles(t, staging)
			// Swap one staged file for a link to an identical file elsewhere.
			external := filepath.Join(sb.outside, "copy")
			put(t, external, read(t, filepath.Join(staging, linked)), 0o600)
			if err := os.Remove(filepath.Join(staging, linked)); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, external, filepath.Join(staging, linked))

			refused(t, open(t, dir, false), s)
			if _, err := os.Lstat(filepath.Join(dir, layout.FileRefreshSecret)); err == nil {
				t.Error("recovery completed the set from a staging directory that contains a symlink")
			}
		})
	}
}

func TestHostile_Symlinks_parentDirectoryLinkKeepsKeysInTheResolvedDirectory(t *testing.T) {
	sb := newSandbox(t)
	real := mustMkdir(t, filepath.Join(sb.root, "real-parent"))
	mustSymlink(t, real, filepath.Join(sb.root, "link-parent"))
	dir := filepath.Join(sb.root, "link-parent", "keys")

	r := open(t, dir, false)
	if r.err != nil {
		t.Fatal(r.err)
	}

	for _, n := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(real, "keys", n)); err != nil {
			t.Errorf("%s missing in the resolved directory: %v", n, err)
		}
	}
	entries, _ := os.ReadDir(sb.root)
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
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			victim := filepath.Join(sb.outside, "victim")
			if tc.existing {
				put(t, victim, []byte("precious\n"), 0o600)
			}
			before := tree(t, sb.outside)
			setFault(t, func(point string) error {
				if point == "staged" {
					return os.Symlink(victim, filepath.Join(dir, layout.FilePrivateKey))
				}
				return nil
			})

			r := open(t, dir, false)

			refused(t, r)
			if !strings.Contains(r.err.Error(), "never writes key material through one") {
				t.Errorf("the refusal does not name the symlink: %v", r.err)
			}
			assertSame(t, "outside", before, tree(t, sb.outside))
			if _, err := os.Lstat(filepath.Join(dir, layout.FilePublicKey)); err == nil {
				t.Error("the public key was published after the private link was refused")
			}
		})
	}
}

func TestHostile_Symlinks_swapMidPublishLeavesVictimAndRecovers(t *testing.T) {
	sb := newSandbox(t)
	dir := sb.keysDir(t)
	victim := filepath.Join(sb.outside, "victim-public")
	before := tree(t, sb.outside)
	setFault(t, func(point string) error {
		if point == "published-private" {
			return os.Symlink(victim, filepath.Join(dir, layout.FilePublicKey))
		}
		return nil
	})
	refused(t, open(t, dir, false))
	assertSame(t, "outside", before, tree(t, sb.outside))

	setFault(t, func(string) error { return nil })
	// The dangling link is still there: recovery must refuse it too, not write
	// through it, and the staging directory must survive as recovery material.
	refused(t, open(t, dir, false))
	assertSame(t, "outside after retry", before, tree(t, sb.outside))
	if len(stagingDirs(t, dir)) == 0 {
		t.Fatal("the staging directory was deleted while the set was incomplete")
	}

	// Once the operator removes the link the same set is completed, not regenerated.
	priv := read(t, filepath.Join(dir, layout.FilePrivateKey))
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	r := open(t, dir, false)
	if r.err != nil {
		t.Fatalf("recovery after removing the link: %v\n%s", r.err, r.log.all())
	}
	if string(read(t, filepath.Join(dir, layout.FilePrivateKey))) != string(priv) {
		t.Error("the private key changed during recovery")
	}
}
