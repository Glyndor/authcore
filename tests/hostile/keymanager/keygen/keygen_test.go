//go:build unix

// Package keygen attacks the authcore-keygen binary, run as a separate process.
package keygen

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
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
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
func setFromDir(t testing.TB, dir string) hostiletest.KeySet {
	t.Helper()
	priv, err := pemcodec.DecodeEd25519PrivatePEM(hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey)), "p")
	if err != nil {
		t.Fatal(err)
	}
	secretHex := hostiletest.Read(t, filepath.Join(dir, layout.FileRefreshSecret))
	secret, err := hex.DecodeString(strings.TrimSpace(string(secretHex)))
	if err != nil {
		t.Fatal(err)
	}
	return hostiletest.KeySet{
		Priv: priv, Pub: priv.Public().(ed25519.PublicKey), Secret: secret,
		PrivPEM: hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey)), PubPEM: hostiletest.Read(t, filepath.Join(dir, layout.FilePublicKey)), SecretHex: secretHex,
	}
}

func TestHostile_Keygen_freshDirectoryIsCompleteAndPrivate(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	out := filepath.Join(sb.Root, "new-keys")

	r := keygen(t, sb.Root, "", "-out", out)

	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	s := setFromDir(t, out)
	hostiletest.AssertNoLeak(t, "keygen output", []hostiletest.KeySet{s}, r.stdout, r.stderr)
	if !strings.Contains(r.stdout, "key id "+s.KeyID()) {
		t.Errorf("stdout does not report the key id of the written set (%s): %q", s.KeyID(), r.stdout)
	}
	want := map[string]os.FileMode{
		layout.FilePrivateKey: 0o600, layout.FilePublicKey: 0o644, layout.FileRefreshSecret: 0o600,
		layout.FileMetadata: 0o600,
	}
	for n, m := range want {
		if got := hostiletest.ModeOf(t, filepath.Join(out, n)).Perm(); got != m {
			t.Errorf("%s is %04o, want %04o", n, got, m)
		}
	}
	if got := hostiletest.ModeOf(t, out).Perm(); got != 0o700 {
		t.Errorf("the directory is %04o, want 0700", got)
	}
	if left := hostiletest.StagingDirs(t, out); len(left) != 0 {
		t.Errorf("staging directories left behind: %v", left)
	}
	hostiletest.Loaded(t, hostiletest.Open(t, out, true), s)
}

func TestHostile_Keygen_neverWritesIntoAnythingThatExists(t *testing.T) {
	cases := map[string]func(t *testing.T, sb hostiletest.Sandbox, target string){
		"empty directory": func(t *testing.T, _ hostiletest.Sandbox, target string) { hostiletest.MustMkdir(t, target) },
		"directory with a live key set": func(t *testing.T, _ hostiletest.Sandbox, target string) {
			hostiletest.NewSet(t).WriteFiles(t, hostiletest.MustMkdir(t, target))
		},
		"non-empty directory": func(t *testing.T, _ hostiletest.Sandbox, target string) {
			hostiletest.Put(t, filepath.Join(hostiletest.MustMkdir(t, target), "notes.txt"), []byte("mine\n"), 0o600)
		},
		"regular file": func(t *testing.T, _ hostiletest.Sandbox, target string) {
			hostiletest.Put(t, target, []byte("data\n"), 0o600)
		},
		"symlink to a directory": func(t *testing.T, sb hostiletest.Sandbox, target string) {
			hostiletest.MustSymlink(t, sb.Outside, target)
		},
		"symlink to a file": func(t *testing.T, sb hostiletest.Sandbox, target string) {
			hostiletest.Put(t, filepath.Join(sb.Outside, "f"), []byte("data\n"), 0o600)
			hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "f"), target)
		},
		"dangling symlink": func(t *testing.T, sb hostiletest.Sandbox, target string) {
			hostiletest.MustSymlink(t, filepath.Join(sb.Outside, "not-there"), target)
		},
		"symlink loop": func(t *testing.T, _ hostiletest.Sandbox, target string) { hostiletest.MustSymlink(t, target, target) },
		"fifo":         func(t *testing.T, _ hostiletest.Sandbox, target string) { hostiletest.Mkfifo(t, target) },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			target := filepath.Join(sb.Root, "target")
			plant(t, sb, target)
			before := hostiletest.Tree(t, sb.Root)

			r := keygen(t, sb.Root, "", "-out", target)

			if r.code != 1 {
				t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
			if r.stdout != "" {
				t.Errorf("a refused run printed to stdout: %q", r.stdout)
			}
		})
	}
}
