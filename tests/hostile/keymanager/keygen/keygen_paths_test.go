//go:build unix

package keygen

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

func TestHostile_Keygen_pathsItCannotCreateFailWithoutResidue(t *testing.T) {
	t.Run("parent missing", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		before := hostiletest.Tree(t, sb.Root)
		r := keygen(t, sb.Root, "", "-out", filepath.Join(sb.Root, "no", "such", "parent"))
		if r.code != 1 || !strings.Contains(r.stderr, "NOT created") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
	})
	t.Run("parent is a file", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		hostiletest.Put(t, filepath.Join(sb.Root, "file"), []byte("x"), 0o600)
		before := hostiletest.Tree(t, sb.Root)
		r := keygen(t, sb.Root, "", "-out", filepath.Join(sb.Root, "file", "keys"))
		if r.code != 1 {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
	})
	t.Run("parent not writable", func(t *testing.T) {
		hostiletest.RequireNonRoot(t)
		sb := hostiletest.NewSandbox(t)
		parent := hostiletest.MustMkdir(t, filepath.Join(sb.Root, "ro"))
		hostiletest.RestoreMode(t, parent)
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		r := keygen(t, sb.Root, "", "-out", filepath.Join(parent, "keys"))
		if r.code != 1 || !strings.Contains(r.stderr, "NOT created") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("something was created in a read-only parent: %v", entries)
		}
	})
	t.Run("name too long", func(t *testing.T) {
		sb := hostiletest.NewSandbox(t)
		before := hostiletest.Tree(t, sb.Root)
		r := keygen(t, sb.Root, "", "-out", strings.Repeat("a", 300))
		if r.code != 1 {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
	})
}

func TestHostile_Keygen_badInvocationsExitWithUsageAndCreateNothing(t *testing.T) {
	cases := map[string][]string{
		"no arguments":        {},
		"empty -out":          {"-out", ""},
		"positional argument": {"-out", "x", "extra"},
		"unknown flag":        {"-nope"},
		"missing value":       {"-out"},
		"help":                {"-h"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			before := hostiletest.Tree(t, sb.Root)
			r := keygen(t, sb.Root, "", args...)
			if r.code != 2 {
				t.Errorf("exit %d, want 2\nstderr: %s", r.code, r.stderr)
			}
			hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
		})
	}
}

func TestHostile_Keygen_awkwardButLegalNamesStayInsideTheirParent(t *testing.T) {
	names := []string{"with space", "-leadingdash", "unié中", "new\nline", "trailing.", "..hidden", strings.Repeat("n", 200)}
	for _, name := range names {
		t.Run(name[:min(len(name), 12)], func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			parent := hostiletest.MustMkdir(t, filepath.Join(sb.Root, "parent"))
			r := keygen(t, parent, "", "-out=./"+name)
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 1 || entries[0].Name() != name {
				t.Errorf("parent holds %v, want only %q", entries, name)
			}
			hostiletest.AssertNoLeak(t, "keygen output", []hostiletest.KeySet{setFromDir(t, filepath.Join(parent, name))}, r.stdout, r.stderr)
		})
	}
}

func TestHostile_Keygen_dotDotAndLinkedParentResolveToTheNamedDirectory(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	real := hostiletest.MustMkdir(t, filepath.Join(sb.Root, "real"))
	hostiletest.MustSymlink(t, real, filepath.Join(sb.Root, "link"))
	r := keygen(t, sb.Root, "", "-out", "link/../real/./keys/../keys")
	// Abs cleans the lexical path to <root>/real/keys, which does not need a parent to be created.
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(real, "keys", layout.FilePrivateKey)); err != nil {
		t.Error(err)
	}
}

func TestHostile_Keygen_secondRunNeverTouchesTheFirstSet(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	out := filepath.Join(sb.Root, "keys")
	if r := keygen(t, sb.Root, "", "-out", out); r.code != 0 {
		t.Fatal(r.stderr)
	}
	before := hostiletest.Tree(t, out)
	r := keygen(t, sb.Root, "", "-out", out)
	if r.code != 1 || !strings.Contains(r.stderr, "already exists") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
	hostiletest.AssertSame(t, "first set", before, hostiletest.Tree(t, out))
}

func TestHostile_Keygen_concurrentRunsOnOnePathHaveOneWinner(t *testing.T) {
	keygenBinary(t)
	for round := range 3 {
		sb := hostiletest.NewSandbox(t)
		out := filepath.Join(sb.Root, "keys")
		const n = 8
		runs := make([]run, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				runs[i] = keygen(t, sb.Root, "", "-out", out)
			}()
		}
		close(start)
		wg.Wait()

		winners := 0
		var winnerOut string
		for _, r := range runs {
			switch r.code {
			case 0:
				winners++
				winnerOut = r.stdout
			case 1:
				if !strings.Contains(r.stderr, "already exists") {
					t.Errorf("round %d: a loser failed for another reason: %q", round, r.stderr)
				}
			default:
				t.Errorf("round %d: exit %d: %s", round, r.code, r.stderr)
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: %d runs claimed success, want exactly one", round, winners)
		}
		s := setFromDir(t, out)
		if !strings.Contains(winnerOut, s.KeyID()) {
			t.Errorf("round %d: the winner reported a key id that is not the one on disk", round)
		}
		hostiletest.Loaded(t, hostiletest.Open(t, out, true), s)
	}
}

func TestHostile_Keygen_failureAfterTheDirectoryExistsSaysSoAndLeaksNothing(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	sb := hostiletest.NewSandbox(t)
	out := filepath.Join(sb.Root, "keys")
	hostiletest.RestoreMode(t, out)

	// umask 0277 makes the directory 0500, so nothing can be written into it.
	r := keygen(t, sb.Root, "0277", "-out", out)

	if r.code != 1 {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "INCOMPLETE") {
		t.Errorf("the failure does not warn that the directory is incomplete: %q", r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("a failed run printed to stdout: %q", r.stdout)
	}
	if err := os.Chmod(out, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range layout.KeyFileNames() {
		if _, err := os.Lstat(filepath.Join(out, n)); err == nil {
			t.Errorf("%s exists after a failed run", n)
		}
	}
}
