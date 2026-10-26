//go:build unix

// Package symlinks attacks the key store with symbolic links in every position:
// key files, metadata, staging entries, KeysDir itself and its parents.
package symlinks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 1: symlinks in every position.

func TestHostile_Symlinks_keyFileToExternalVictim(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		victim := filepath.Join(sb.Outside, "victim.txt")
		hostiletest.Put(t, victim, []byte("not a key\n"), 0o644)
		hostiletest.MustSymlink(t, victim, filepath.Join(dir, layout.FilePrivateKey))
		before := hostiletest.Tree(t, sb.Outside)

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly))

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
		for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
			if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
				t.Errorf("%s was created next to a symlinked private key", n)
			}
		}
	})
}

func TestHostile_Symlinks_danglingKeyFilesAimedOutside(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		for _, n := range layout.KeyFileNames() {
			hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "planted-"+n), filepath.Join(dir, n))
		}
		before := hostiletest.Tree(t, sb.Outside)

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly))

		// A write through the link would have created the planted file.
		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_Symlinks_oneDanglingKeyAmongRealOnes(t *testing.T) {
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.WithSet(t, s)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "planted"), filepath.Join(dir, name))
			before := hostiletest.Tree(t, sb.Outside)

			hostiletest.Refused(t, hostiletest.Open(t, dir, false), s)

			hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
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
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				link := filepath.Join(dir, name)
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				hostiletest.MustSymlink(t, target, link)

				r := hostiletest.Open(t, dir, true)
				hostiletest.Refused(t, r, s)

				// The refusal may name the path, never the content of the file.
				first, _, _ := strings.Cut(string(hostiletest.Read(t, target)), "\n")
				if len(first) > 8 && strings.Contains(r.Err.Error()+r.Log.All(), first) {
					t.Errorf("the content of %s reached the error or the log: %q", target, first)
				}
			})
		}
	}
}

func TestHostile_Symlinks_loopInKeyFile(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		a, b := filepath.Join(dir, "loop-a"), filepath.Join(dir, "loop-b")
		hostiletest.MustSymlink(t, b, a)
		hostiletest.MustSymlink(t, a, b)
		hostiletest.MustSymlink(t, a, filepath.Join(dir, layout.FilePrivateKey))

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly))
	})
}

func TestHostile_Symlinks_selfLinkAsMetadata(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		s := hostiletest.NewSet(t)
		dir := sb.WithSet(t, s)
		hostiletest.MustSymlink(t, filepath.Join(dir, layout.FileMetadata), filepath.Join(dir, layout.FileMetadata))
		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
	})
}

func TestHostile_Symlinks_kubernetesProjectionLoadsAndLoadOnlyWritesNothing(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	// A Secret volume projects each file as a link through ..data to a
	// timestamped directory. Reads must follow, which is the documented reason
	// the read path does not refuse links.
	stamp := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "..2026_10_25"))
	s.WriteFiles(t, stamp)
	hostiletest.MustSymlink(t, "..2026_10_25", filepath.Join(sb.Outside, "..data"))
	dir := sb.KeysDir(t)
	for _, n := range layout.KeyFileNames() {
		hostiletest.MustSymlink(t, filepath.Join("..data", n), filepath.Join(sb.Outside, n))
		hostiletest.MustSymlink(t, filepath.Join(sb.Outside, n), filepath.Join(dir, n))
	}
	beforeOutside, beforeDir := hostiletest.Tree(t, sb.Outside), hostiletest.Tree(t, dir)

	hostiletest.Loaded(t, hostiletest.Open(t, dir, true), s)
	hostiletest.AssertSame(t, "outside after load-only", beforeOutside, hostiletest.Tree(t, sb.Outside))
	hostiletest.AssertSame(t, "KeysDir after load-only", beforeDir, hostiletest.Tree(t, dir))

	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
	hostiletest.AssertSame(t, "outside after New", beforeOutside, hostiletest.Tree(t, sb.Outside))
	for _, n := range layout.KeyFileNames() {
		if fi, _ := os.Lstat(filepath.Join(dir, n)); fi == nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("New replaced the projected link %s", n)
		}
	}
}

func TestHostile_Symlinks_pairSplitAcrossTwoSetsIsRefused(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		a, b := hostiletest.NewSet(t), hostiletest.NewSet(t)
		dirA := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "a"))
		dirB := hostiletest.MustMkdir(t, filepath.Join(sb.Outside, "b"))
		a.WriteFiles(t, dirA)
		b.WriteFiles(t, dirB)
		dir := sb.KeysDir(t)
		hostiletest.MustSymlink(t, filepath.Join(dirA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
		hostiletest.MustSymlink(t, filepath.Join(dirB, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))
		hostiletest.MustSymlink(t, filepath.Join(dirA, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), a, b)
	})
}
