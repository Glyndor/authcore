//go:build unix

package hostile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// Class 7: the authcore-keygen binary, run as a separate process.

var (
	keygenOnce sync.Once
	keygenBin  string
	keygenErr  error
	keygenDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if keygenDir != "" {
		_ = os.RemoveAll(keygenDir)
	}
	os.Exit(code)
}

// keygenBinary builds cmd/authcore-keygen once for the whole run.
func keygenBinary(t testing.TB) string {
	t.Helper()
	keygenOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			keygenErr = err
			return
		}
		keygenDir, keygenErr = os.MkdirTemp("", "authcore-keygen-bin")
		if keygenErr != nil {
			return
		}
		keygenBin = filepath.Join(keygenDir, "authcore-keygen")
		out, err := exec.CommandContext(context.Background(), goTool, "build", "-o", keygenBin, "github.com/Glyndor/authcore/cmd/authcore-keygen").CombinedOutput()
		if err != nil {
			keygenErr = errors.New("go build failed: " + err.Error() + "\n" + string(out))
		}
	})
	if keygenErr != nil {
		t.Skipf("cannot build authcore-keygen here: %v", keygenErr)
	}
	return keygenBin
}

type run struct {
	code           int
	stdout, stderr string
}

// keygen runs the binary in cwd with a minimal environment. umask, when not
// empty, is applied by a shell wrapper before exec.
func keygen(t testing.TB, cwd, umask string, args ...string) run {
	t.Helper()
	bin := keygenBinary(t)
	var cmd *exec.Cmd
	if umask != "" {
		cmd = exec.CommandContext(t.Context(), "sh", append([]string{"-c", `umask ` + umask + `; exec "$0" "$@"`, bin}, args...)...)
	} else {
		cmd = exec.CommandContext(t.Context(), bin, args...)
	}
	cmd.Dir = cwd
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return run{code, out.String(), errb.String()}
}

// setFromDir reads a generated directory back as a keySet.
func setFromDir(t testing.TB, dir string) keySet {
	t.Helper()
	priv, err := pemcodec.DecodeEd25519PrivatePEM(read(t, filepath.Join(dir, layout.FilePrivateKey)), "p")
	if err != nil {
		t.Fatal(err)
	}
	secretHex := read(t, filepath.Join(dir, layout.FileRefreshSecret))
	secret, err := hex.DecodeString(strings.TrimSpace(string(secretHex)))
	if err != nil {
		t.Fatal(err)
	}
	return keySet{
		priv: priv, pub: priv.Public().(ed25519.PublicKey), secret: secret,
		privPEM: read(t, filepath.Join(dir, layout.FilePrivateKey)), pubPEM: read(t, filepath.Join(dir, layout.FilePublicKey)), secretHex: secretHex,
	}
}

func TestHostile_Keygen_freshDirectoryIsCompleteAndPrivate(t *testing.T) {
	sb := newSandbox(t)
	out := filepath.Join(sb.root, "new-keys")

	r := keygen(t, sb.root, "", "-out", out)

	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	s := setFromDir(t, out)
	assertNoLeak(t, "keygen output", []keySet{s}, r.stdout, r.stderr)
	if !strings.Contains(r.stdout, "key id "+s.keyID()) {
		t.Errorf("stdout does not report the key id of the written set (%s): %q", s.keyID(), r.stdout)
	}
	want := map[string]os.FileMode{
		layout.FilePrivateKey: 0o600, layout.FilePublicKey: 0o644, layout.FileRefreshSecret: 0o600,
		layout.FileMetadata: 0o600,
	}
	for n, m := range want {
		if got := modeOf(t, filepath.Join(out, n)).Perm(); got != m {
			t.Errorf("%s is %04o, want %04o", n, got, m)
		}
	}
	if got := modeOf(t, out).Perm(); got != 0o700 {
		t.Errorf("the directory is %04o, want 0700", got)
	}
	if left := stagingDirs(t, out); len(left) != 0 {
		t.Errorf("staging directories left behind: %v", left)
	}
	loaded(t, open(t, out, true), s)
}

func TestHostile_Keygen_neverWritesIntoAnythingThatExists(t *testing.T) {
	cases := map[string]func(t *testing.T, sb sandbox, target string){
		"empty directory": func(t *testing.T, _ sandbox, target string) { mustMkdir(t, target) },
		"directory with a live key set": func(t *testing.T, _ sandbox, target string) {
			newSet(t).writeFiles(t, mustMkdir(t, target))
		},
		"non-empty directory": func(t *testing.T, _ sandbox, target string) {
			put(t, filepath.Join(mustMkdir(t, target), "notes.txt"), []byte("mine\n"), 0o600)
		},
		"regular file": func(t *testing.T, _ sandbox, target string) { put(t, target, []byte("data\n"), 0o600) },
		"symlink to a directory": func(t *testing.T, sb sandbox, target string) {
			mustSymlink(t, sb.outside, target)
		},
		"symlink to a file": func(t *testing.T, sb sandbox, target string) {
			put(t, filepath.Join(sb.outside, "f"), []byte("data\n"), 0o600)
			mustSymlink(t, filepath.Join(sb.outside, "f"), target)
		},
		"dangling symlink": func(t *testing.T, sb sandbox, target string) {
			mustSymlink(t, filepath.Join(sb.outside, "not-there"), target)
		},
		"symlink loop": func(t *testing.T, _ sandbox, target string) { mustSymlink(t, target, target) },
		"fifo":         func(t *testing.T, _ sandbox, target string) { mkfifo(t, target) },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			target := filepath.Join(sb.root, "target")
			plant(t, sb, target)
			before := tree(t, sb.root)

			r := keygen(t, sb.root, "", "-out", target)

			if r.code != 1 {
				t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			assertSame(t, "sandbox", before, tree(t, sb.root))
			if r.stdout != "" {
				t.Errorf("a refused run printed to stdout: %q", r.stdout)
			}
		})
	}
}

func TestHostile_Keygen_pathsItCannotCreateFailWithoutResidue(t *testing.T) {
	t.Run("parent missing", func(t *testing.T) {
		sb := newSandbox(t)
		before := tree(t, sb.root)
		r := keygen(t, sb.root, "", "-out", filepath.Join(sb.root, "no", "such", "parent"))
		if r.code != 1 || !strings.Contains(r.stderr, "NOT created") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		assertSame(t, "sandbox", before, tree(t, sb.root))
	})
	t.Run("parent is a file", func(t *testing.T) {
		sb := newSandbox(t)
		put(t, filepath.Join(sb.root, "file"), []byte("x"), 0o600)
		before := tree(t, sb.root)
		r := keygen(t, sb.root, "", "-out", filepath.Join(sb.root, "file", "keys"))
		if r.code != 1 {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		assertSame(t, "sandbox", before, tree(t, sb.root))
	})
	t.Run("parent not writable", func(t *testing.T) {
		requireNonRoot(t)
		sb := newSandbox(t)
		parent := mustMkdir(t, filepath.Join(sb.root, "ro"))
		restoreMode(t, parent)
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		r := keygen(t, sb.root, "", "-out", filepath.Join(parent, "keys"))
		if r.code != 1 || !strings.Contains(r.stderr, "NOT created") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("something was created in a read-only parent: %v", entries)
		}
	})
	t.Run("name too long", func(t *testing.T) {
		sb := newSandbox(t)
		before := tree(t, sb.root)
		r := keygen(t, sb.root, "", "-out", strings.Repeat("a", 300))
		if r.code != 1 {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
		assertSame(t, "sandbox", before, tree(t, sb.root))
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
			sb := newSandbox(t)
			before := tree(t, sb.root)
			r := keygen(t, sb.root, "", args...)
			if r.code != 2 {
				t.Errorf("exit %d, want 2\nstderr: %s", r.code, r.stderr)
			}
			assertSame(t, "sandbox", before, tree(t, sb.root))
		})
	}
}

func TestHostile_Keygen_awkwardButLegalNamesStayInsideTheirParent(t *testing.T) {
	names := []string{"with space", "-leadingdash", "unié中", "new\nline", "trailing.", "..hidden", strings.Repeat("n", 200)}
	for _, name := range names {
		t.Run(name[:min(len(name), 12)], func(t *testing.T) {
			sb := newSandbox(t)
			parent := mustMkdir(t, filepath.Join(sb.root, "parent"))
			r := keygen(t, parent, "", "-out=./"+name)
			if r.code != 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 1 || entries[0].Name() != name {
				t.Errorf("parent holds %v, want only %q", entries, name)
			}
			assertNoLeak(t, "keygen output", []keySet{setFromDir(t, filepath.Join(parent, name))}, r.stdout, r.stderr)
		})
	}
}

func TestHostile_Keygen_dotDotAndLinkedParentResolveToTheNamedDirectory(t *testing.T) {
	sb := newSandbox(t)
	real := mustMkdir(t, filepath.Join(sb.root, "real"))
	mustSymlink(t, real, filepath.Join(sb.root, "link"))
	r := keygen(t, sb.root, "", "-out", "link/../real/./keys/../keys")
	// Abs cleans the lexical path to <root>/real/keys, which does not need a parent to be created.
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(real, "keys", layout.FilePrivateKey)); err != nil {
		t.Error(err)
	}
}

func TestHostile_Keygen_secondRunNeverTouchesTheFirstSet(t *testing.T) {
	sb := newSandbox(t)
	out := filepath.Join(sb.root, "keys")
	if r := keygen(t, sb.root, "", "-out", out); r.code != 0 {
		t.Fatal(r.stderr)
	}
	before := tree(t, out)
	r := keygen(t, sb.root, "", "-out", out)
	if r.code != 1 || !strings.Contains(r.stderr, "already exists") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
	assertSame(t, "first set", before, tree(t, out))
}

func TestHostile_Keygen_concurrentRunsOnOnePathHaveOneWinner(t *testing.T) {
	keygenBinary(t)
	for round := range 3 {
		sb := newSandbox(t)
		out := filepath.Join(sb.root, "keys")
		const n = 8
		runs := make([]run, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				runs[i] = keygen(t, sb.root, "", "-out", out)
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
		if !strings.Contains(winnerOut, s.keyID()) {
			t.Errorf("round %d: the winner reported a key id that is not the one on disk", round)
		}
		loaded(t, open(t, out, true), s)
	}
}

func TestHostile_Keygen_failureAfterTheDirectoryExistsSaysSoAndLeaksNothing(t *testing.T) {
	requireNonRoot(t)
	sb := newSandbox(t)
	out := filepath.Join(sb.root, "keys")
	restoreMode(t, out)

	// umask 0277 makes the directory 0500, so nothing can be written into it.
	r := keygen(t, sb.root, "0277", "-out", out)

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
