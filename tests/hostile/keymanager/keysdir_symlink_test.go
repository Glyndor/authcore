//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 1b: the KeysDir path itself is a symlink. Only the last component is
// refused; links in parent components are covered in symlinks_test.go.

// wantLinkRefusal asserts the refusal names the problem and both ways out.
func wantLinkRefusal(t testing.TB, r result) {
	t.Helper()
	refused(t, r)
	for _, want := range []string{"symbolic link", "filepath.EvalSymlinks", "mount the volume"} {
		if !strings.Contains(r.err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, r.err)
		}
	}
}

func TestHostile_KeysDirSymlink_isRefusedAndTargetIsUntouched(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		requireNonRoot(t)
		sb := newSandbox(t)
		target := mustMkdir(t, filepath.Join(sb.outside, "target"))
		if err := os.Chmod(target, 0o755); err != nil {
			t.Fatal(err)
		}
		mustSymlink(t, target, sb.keys)
		before := tree(t, sb.outside)

		wantLinkRefusal(t, open(t, sb.keys, loadOnly))

		assertSame(t, "outside", before, tree(t, sb.outside))
		if got := modeOf(t, target).Perm(); got != 0o755 {
			t.Errorf("the target mode changed to %04o", got)
		}
	})
}

func TestHostile_KeysDirSymlink_toACompleteSetIsRefused(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		s := newSet(t)
		target := mustMkdir(t, filepath.Join(sb.outside, "set"))
		s.writeFiles(t, target)
		mustSymlink(t, target, sb.keys)
		before := tree(t, sb.outside)

		r := open(t, sb.keys, loadOnly)

		wantLinkRefusal(t, r)
		assertNoLeak(t, "refusal", []keySet{s}, r.err.Error(), r.log.all())
		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_KeysDirSymlink_danglingIsRefusedWithoutCreatingTheTarget(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		mustSymlink(t, filepath.Join(sb.outside, "never"), sb.keys)
		before := tree(t, sb.outside)

		wantLinkRefusal(t, open(t, sb.keys, loadOnly))

		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_KeysDirSymlink_spellingsOfTheSameLinkAreRefused(t *testing.T) {
	for _, suffix := range []string{"/", "//", "/.", "/./", "/./."} {
		t.Run("suffix "+suffix, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				requireNonRoot(t)
				sb := newSandbox(t)
				target := mustMkdir(t, filepath.Join(sb.outside, "target"))
				if err := os.Chmod(target, 0o755); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, target, sb.keys)
				before := tree(t, sb.outside)

				wantLinkRefusal(t, open(t, sb.keys+suffix, loadOnly))

				assertSame(t, "outside", before, tree(t, sb.outside))
			})
		})
	}
}

func TestHostile_KeysDirSymlink_chainOfLinksIsRefused(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		target := mustMkdir(t, filepath.Join(sb.outside, "target"))
		hop := filepath.Join(sb.outside, "hop")
		mustSymlink(t, target, hop)
		mustSymlink(t, hop, sb.keys)
		before := tree(t, sb.outside)

		wantLinkRefusal(t, open(t, sb.keys, loadOnly))

		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_KeysDirSymlink_aLinkInTheParentStillLoadsAndGenerates(t *testing.T) {
	sb := newSandbox(t)
	real := mustMkdir(t, filepath.Join(sb.root, "real"))
	mustSymlink(t, real, filepath.Join(sb.root, "alias"))
	dir := filepath.Join(sb.root, "alias", "keys")

	r := open(t, dir, false)
	if r.err != nil {
		t.Fatalf("a link in a parent component must not be refused: %v", r.err)
	}
	loaded(t, open(t, dir, true), keySet{
		priv: r.keys.PrivateKey(), pub: r.keys.PublicKey(), secret: r.keys.RefreshSecret(),
	})
	for _, n := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(real, "keys", n)); err != nil {
			t.Errorf("%s missing in the resolved directory: %v", n, err)
		}
	}
}

func TestHostile_KeysDirSymlink_keygenRefusesALinkAsOut(t *testing.T) {
	sb := newSandbox(t)
	target := mustMkdir(t, filepath.Join(sb.outside, "target"))
	mustSymlink(t, target, sb.keys)
	before := tree(t, sb.outside)

	got := keygen(t, sb.root, "", "-out", sb.keys)

	if got.code == 0 || got.stdout != "" {
		t.Fatalf("keygen accepted a symlink as -out: code %d, stdout %q", got.code, got.stdout)
	}
	if !strings.Contains(got.stderr, "symbolic link") || !strings.Contains(got.stderr, "filepath.EvalSymlinks") {
		t.Errorf("keygen does not explain the link refusal: %q", got.stderr)
	}
	assertSame(t, "outside", before, tree(t, sb.outside))
}
