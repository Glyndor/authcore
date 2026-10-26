//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// Scripts branch on these codes, so they are exact: 0 success, 1 runtime
// failure, 2 usage error. A failure that exits 0 would let a deployment go on
// with a directory that holds no keys.
func TestRunExitCodesAreExact(t *testing.T) {
	existing := t.TempDir()
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"missing -out", nil, 2},
		{"unknown flag", []string{"-bogus"}, 2},
		{"positional argument", []string{"-out", filepath.Join(t.TempDir(), "k"), "extra"}, 2},
		{"directory exists", []string{"-out", existing}, 1},
		{"missing parent", []string{"-out", filepath.Join(t.TempDir(), "a", "b")}, 1},
		{"success", []string{"-out", filepath.Join(t.TempDir(), "keys")}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _, _ := runKeygen(t, c.args); code != c.want {
				t.Fatalf("exit code = %d, want %d", code, c.want)
			}
		})
	}
}

func TestRunCreatesTheDirectoryOwnerOnly(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
	out := filepath.Join(t.TempDir(), "keys")

	if code, _, stderr := runKeygen(t, []string{"-out", out}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %04o, want 0700", got)
	}
}

// helperEnv makes the test binary run main() instead of the tests, so the
// process exit status can be observed.
const helperEnv = "AUTHCORE_KEYGEN_TEST_MAIN"

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("only runs as the child of TestMainExitsWithTheStatusOfRun")
	}
	args := strings.Split(os.Getenv(helperEnv+"_ARGS"), "\x1f")
	os.Args = append([]string{"authcore-keygen"}, args...)
	main()
}

func TestMainExitsWithTheStatusOfRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "keys")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"usage error", []string{"-bogus"}, 2},
		{"success", []string{"-out", out}, 0},
		{"failure", []string{"-out", out}, 1}, // the directory now exists
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainHelperProcess$")
			cmd.Env = append(os.Environ(), helperEnv+"=1", helperEnv+"_ARGS="+strings.Join(c.args, "\x1f"))
			err := cmd.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.want {
				t.Fatalf("main exited with %d, want %d", code, c.want)
			}
		})
	}
}

// When generation fails after the directory exists, the tool says the
// directory is incomplete and exits 1; it must not go on to print a key id.
func TestRunReportsAnIncompleteDirectoryWhenGenerationFails(t *testing.T) {
	prev := seams.FaultAt
	seams.FaultAt = func(point string) error {
		if point == "staged" {
			return errors.New("simulated failure")
		}
		return nil
	}
	t.Cleanup(func() { seams.FaultAt = prev })
	out := filepath.Join(t.TempDir(), "keys")

	code, stdout, stderr := runKeygen(t, []string{"-out", out})
	if code != 1 || stdout != "" || !strings.Contains(stderr, "INCOMPLETE") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
