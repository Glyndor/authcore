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

// Class 1b: the KeysDir path itself is a symlink. Only the last component is
// refused; links in parent components are covered in symlinks_test.go.

// wantLinkRefusal asserts the refusal names the problem and both ways out.
func wantLinkRefusal(t testing.TB, r hostiletest.Result) {
	t.Helper()
	hostiletest.Refused(t, r)
	for _, want := range []string{"symbolic link", "filepath.EvalSymlinks", "mount the volume"} {
		if !strings.Contains(r.Err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, r.Err)
		}
	}
}

func TestHostile_KeysDirSymlink_isRefusedAndTargetIsUntouched(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		hostiletest.RequireNonRoot(t)
		sb := hostiletest.NewSandbox(t)
		target := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "target"))
		if err := os.Chmod(target, 0o755); err != nil {
			t.Fatal(err)
		}
		hostiletest.MustSymlink(t, target, sb.Keys)
		before := hostiletest.Tree(t, sb.Outside)

		wantLinkRefusal(t, hostiletest.Open(t, sb.Keys, loadOnly))

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
		if got := hostiletest.ModeOf(t, target).Perm(); got != 0o755 {
			t.Errorf("the target mode changed to %04o", got)
		}
	})
}

func TestHostile_KeysDirSymlink_toACompleteSetIsRefused(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		s := hostiletest.NewSet(t)
		target := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "set"))
		s.WriteFiles(t, target)
		hostiletest.MustSymlink(t, target, sb.Keys)
		before := hostiletest.Tree(t, sb.Outside)

		r := hostiletest.Open(t, sb.Keys, loadOnly)

		wantLinkRefusal(t, r)
		hostiletest.AssertNoLeak(t, "refusal", []hostiletest.KeySet{s}, r.Err.Error(), r.Log.All())
		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_KeysDirSymlink_danglingIsRefusedWithoutCreatingTheTarget(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "never"), sb.Keys)
		before := hostiletest.Tree(t, sb.Outside)

		wantLinkRefusal(t, hostiletest.Open(t, sb.Keys, loadOnly))

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_KeysDirSymlink_spellingsOfTheSameLinkAreRefused(t *testing.T) {
	for _, suffix := range []string{"/", "//", "/.", "/./", "/./."} {
		t.Run("suffix "+suffix, func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				hostiletest.RequireNonRoot(t)
				sb := hostiletest.NewSandbox(t)
				target := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "target"))
				if err := os.Chmod(target, 0o755); err != nil {
					t.Fatal(err)
				}
				hostiletest.MustSymlink(t, target, sb.Keys)
				before := hostiletest.Tree(t, sb.Outside)

				wantLinkRefusal(t, hostiletest.Open(t, sb.Keys+suffix, loadOnly))

				hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
			})
		})
	}
}

func TestHostile_KeysDirSymlink_chainOfLinksIsRefused(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		target := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "target"))
		hop := filepath.Join(sb.Outside, "hop")
		hostiletest.MustSymlink(t, target, hop)
		hostiletest.MustSymlink(t, hop, sb.Keys)
		before := hostiletest.Tree(t, sb.Outside)

		wantLinkRefusal(t, hostiletest.Open(t, sb.Keys, loadOnly))

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_KeysDirSymlink_aLinkInTheParentStillLoadsAndGenerates(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	real := hostiletest.MustMkdir(t, filepath.Join(sb.Root, "real"))
	hostiletest.MustSymlink(t, real, filepath.Join(sb.Root, "alias"))
	dir := filepath.Join(sb.Root, "alias", "keys")

	r := hostiletest.Open(t, dir, false)
	if r.Err != nil {
		t.Fatalf("a link in a parent component must not be refused: %v", r.Err)
	}
	hostiletest.Loaded(t, hostiletest.Open(t, dir, true), hostiletest.KeySet{
		Priv: r.Keys.PrivateKey(), Pub: r.Keys.PublicKey(), Secret: r.Keys.RefreshSecret(),
	})
	for _, n := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(real, "keys", n)); err != nil {
			t.Errorf("%s missing in the resolved directory: %v", n, err)
		}
	}
}
