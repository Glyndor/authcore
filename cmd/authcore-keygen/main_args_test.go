package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoArgumentsIsAUsageError covers the missing-flag usage error: exit 2 and a usage
// message that mentions the only flag the tool accepts.
func TestNoArgumentsIsAUsageError(t *testing.T) {
	code, stdout, stderr := runKeygen(t, nil)

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "-out") {
		t.Fatalf("stderr does not mention -out: %q", stderr)
	}
}

// TestExtraArgumentIsAUsageError covers the unexpected-positional-argument usage error.
func TestExtraArgumentIsAUsageError(t *testing.T) {
	code, stdout, stderr := runKeygen(t, []string{"-out", filepath.Join(t.TempDir(), "keys"), "extra"})

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "unexpected positional argument") {
		t.Fatalf("stderr missing positional-argument notice: %q", stderr)
	}
}

// TestHelpFlag covers the help-path: -h / -help is a usage error in the
// flag package's contract, and the tool must surface it as exit 2 without
// doing any of the work the other paths do.
func TestHelpFlag(t *testing.T) {
	code, stdout, stderr := runKeygen(t, []string{"-h"})

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	// The flag package prints its own usage on -h. We do not add ours on
	// top of it.
	if !strings.Contains(stderr, "authcore-keygen") {
		t.Fatalf("stderr does not mention the program name: %q", stderr)
	}
}

// TestInvalidFlag covers a non-help parse error: an unknown flag makes the
// flag package return a non-ErrHelp error, and the tool prints its own usage
// banner on top so the operator sees both the failure and what to fix.
func TestInvalidFlag(t *testing.T) {
	code, stdout, stderr := runKeygen(t, []string{"-no-such-flag"})

	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "usage: authcore-keygen") {
		t.Fatalf("stderr does not contain the usage banner: %q", stderr)
	}
}

// stdout is two lines that scripts read. A legal path with a line break in it
// used to print a forged "key id" line after the real one; it is written
// quoted now, and a path without control characters is written as it is.
func TestControlCharactersInTheOutputPathCannotForgeALine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow control characters in a file name, so the directory cannot exist")
	}
	for _, name := range []string{"x\nkey id 0000000000000000", "x\ry", "x\ty", "x\x7f"} {
		dir := filepath.Join(t.TempDir(), name)
		code, stdout, stderr := runKeygen(t, []string{"-out", dir})

		if code != 0 {
			t.Fatalf("%q: exit code = %d; stderr=%q", name, code, stderr)
		}
		lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "wrote \"") || !strings.HasPrefix(lines[1], "key id ") {
			t.Errorf("%q: stdout is not two lines, the first quoted: %q", name, stdout)
		}
	}
}

func TestAPlainOutputPathIsWrittenAsItIs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plain keys")
	_, stdout, _ := runKeygen(t, []string{"-out", dir})
	if !strings.HasPrefix(stdout, "wrote "+dir+"\n") {
		t.Errorf("stdout = %q, want the path unquoted", stdout)
	}
}
