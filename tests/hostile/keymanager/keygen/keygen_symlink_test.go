//go:build unix

package keygen

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

func TestHostile_KeysDirSymlink_keygenRefusesALinkAsOut(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	target := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "target"))
	hostiletest.MustSymlink(t, target, sb.Keys)
	before := hostiletest.Tree(t, sb.Outside)

	got := keygen(t, sb.Root, "", "-out", sb.Keys)

	if got.code == 0 || got.stdout != "" {
		t.Fatalf("keygen accepted a symlink as -out: code %d, stdout %q", got.code, got.stdout)
	}
	if !strings.Contains(got.stderr, "symbolic link") || !strings.Contains(got.stderr, "filepath.EvalSymlinks") {
		t.Errorf("keygen does not explain the link refusal: %q", got.stderr)
	}
	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
}
