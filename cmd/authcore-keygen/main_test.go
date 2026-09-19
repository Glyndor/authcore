package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// keygenSilentLog discards every log line. It exists so tests that call
// keymanager.Load on the freshly written directory do not write Warn lines
// into the test output (a leftover staging directory would surface as one).
type keygenSilentLog struct{}

func (keygenSilentLog) Info(string, ...any) {}
func (keygenSilentLog) Warn(string, ...any) {}

// runKeygen is a small helper that invokes run with fresh buffers and
// returns the exit code, the captured stdout and the captured stderr.
func runKeygen(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

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

// TestWritesANewKeySet covers the happy path: a fresh directory receives the key
// set, stdout holds exactly the two lines the contract promises, and key
// material stays off the wire.
func TestWritesANewKeySet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	code, stdout, stderr := runKeygen(t, []string{"-out", dir})

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty on success", stderr)
	}

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout has %d lines, want exactly 2:\n%s", len(lines), stdout)
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", dir, err)
	}

	wantWrote := "wrote " + absDir
	if lines[0] != wantWrote {
		t.Fatalf("line 0 = %q, want %q", lines[0], wantWrote)
	}

	if !strings.HasPrefix(lines[1], "key id ") {
		t.Fatalf("line 1 = %q, want a \"key id \" prefix", lines[1])
	}
	printedID := strings.TrimPrefix(lines[1], "key id ")

	km, err := keymanager.Load(absDir, keygenSilentLog{})
	if err != nil {
		t.Fatalf("keymanager.Load(%q): %v", absDir, err)
	}
	if km.KeyID() != printedID {
		t.Fatalf("printed key id %q does not match KeyManager.KeyID() %q",
			printedID, km.KeyID())
	}

	// No key material in stdout. The private PEM file holds "PRIVATE KEY",
	// and the refresh secret file is the raw hex bytes of the HMAC key.
	if strings.Contains(stdout, "PRIVATE KEY") {
		t.Fatalf("stdout contains %q (private key material leaked): %q",
			"PRIVATE KEY", stdout)
	}
	secretBytes, err := os.ReadFile(filepath.Join(absDir, "refresh_secret.key"))
	if err != nil {
		t.Fatalf("read refresh_secret.key: %v", err)
	}
	if strings.Contains(stdout, strings.TrimSpace(string(secretBytes))) {
		t.Fatalf("stdout contains the refresh secret hex; key material leaked")
	}

	// File presence and (where the platform honours Unix permission bits)
	// file modes. Skip the mode check on Windows: the bits are not enforced
	// there, so the test would be a false negative.
	expectModes := []struct {
		name string
		want os.FileMode
	}{
		{"ed25519_private.pem", 0o600},
		{"ed25519_public.pem", 0o644},
		{"refresh_secret.key", 0o600},
	}
	for _, em := range expectModes {
		path := filepath.Join(absDir, em.name)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %q: %v", path, err)
		}
		if runtime.GOOS == "windows" {
			continue // file modes are not honoured on Windows
		}
		if got := fi.Mode().Perm(); got != em.want {
			t.Fatalf("%s mode = %o, want %o", em.name, got, em.want)
		}
	}
}

// TestRefusesAnExistingDirectory covers the refusal path when the target directory already
// exists. The tool must report the condition on stderr, leave the directory
// untouched, and exit non-zero so a shell script can branch on the failure.
func TestRefusesAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("setup Mkdir: %v", err)
	}

	code, stdout, stderr := runKeygen(t, []string{"-out", dir})

	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Fatalf("stderr does not mention %q: %q", "already exists", stderr)
	}

	// The refusal message must not invite the operator to remove the
	// existing directory: an existing path may hold a key set that is in
	// use, and removing it loses every encrypted column.
	if strings.Contains(strings.ToLower(stderr), "remove") {
		t.Fatalf("stderr must not invite the operator to remove the existing directory: %q", stderr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory is not empty after refusal: %v", entries)
	}
}

// TestLeavesAnExistingKeySetUntouched covers the refusal path when the target directory
// already holds a complete key set from an earlier run. The tool must exit
// non-zero AND every byte of every file written by the first run must be
// exactly the same afterwards: this is the safety property that makes the
// tool safe to script as `if existing_keys; then ...; fi`.
func TestLeavesAnExistingKeySetUntouched(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

	// First run populates the directory.
	if code, _, errOut := runKeygen(t, []string{"-out", dir}); code != 0 {
		t.Fatalf("setup run failed: exit=%d stderr=%q", code, errOut)
	}

	// Snapshot every file the first run wrote, plus the directory mode.
	type snapshot struct {
		data []byte
		mode os.FileMode
	}
	before := map[string]snapshot{}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", dir, err)
	}
	for _, name := range []string{
		"ed25519_private.pem",
		"ed25519_public.pem",
		"refresh_secret.key",
		"metadata.json",
		".gitignore",
	} {
		path := filepath.Join(absDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("snapshot read %q: %v", path, err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("snapshot stat %q: %v", path, err)
		}
		before[name] = snapshot{data: data, mode: fi.Mode().Perm()}
	}

	// Second run must refuse.
	code, stdout, stderr := runKeygen(t, []string{"-out", dir})

	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Fatalf("stderr does not mention %q: %q", "already exists", stderr)
	}

	// Every file's bytes and mode are unchanged.
	for name, snap := range before {
		path := filepath.Join(absDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("re-read %q: %v", path, err)
		}
		if !bytes.Equal(data, snap.data) {
			t.Fatalf("%q bytes changed: was %q, now %q", name, snap.data, data)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("re-stat %q: %v", path, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != snap.mode {
			t.Fatalf("%q mode changed: was %o, now %o", name, snap.mode, fi.Mode().Perm())
		}
	}
}

// TestRefusesAMissingParent covers the case where the parent of PATH does not
// exist. Mkdir (not MkdirAll) makes this an error rather than a silently
// created tree, and the tool must not create the leaf directory either.
func TestRefusesAMissingParent(t *testing.T) {
	missingParent := filepath.Join(t.TempDir(), "no-such-parent")
	dir := filepath.Join(missingParent, "keys")

	if _, err := os.Stat(missingParent); !os.IsNotExist(err) {
		t.Fatalf("parent %q should not exist before the run; got err=%v", missingParent, err)
	}

	code, stdout, stderr := runKeygen(t, []string{"-out", dir})

	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}

	if _, err := os.Stat(missingParent); !os.IsNotExist(err) {
		t.Fatalf("parent %q was created by the run; got err=%v", missingParent, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("leaf %q was created by the run; got err=%v", dir, err)
	}

	// The error message points at the leaf path, not the parent: that is
	// what the operator sees when they paste it back to the shell.
	if !strings.Contains(stderr, dir) && !strings.Contains(stderr, missingParent) {
		t.Fatalf("stderr does not name the failing path: %q", stderr)
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

// TestFilepathAbsError covers the rare case where filepath.Abs cannot
// resolve the working directory. The test puts the process in a directory
// that no longer exists, so Getwd returns ENOENT, and run() refuses rather
// than guessing at a path.
func TestFilepathAbsError(t *testing.T) {
	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("setup Getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origCwd); err != nil {
			t.Logf("could not restore cwd to %q: %v", origCwd, err)
		}
	})

	// Make a temp dir, chdir into it, then delete it. The process's cwd
	// now points at a directory that no longer exists, and Getwd returns
	// the kernel's "no such file or directory" for any path resolution
	// that touches it.
	tmpDir, err := os.MkdirTemp("", "authcore-keygen-abs-")
	if err != nil {
		t.Fatalf("setup MkdirTemp: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("setup Chdir(%q): %v", tmpDir, err)
	}
	if err := os.RemoveAll(tmpDir); err != nil {
		t.Fatalf("setup RemoveAll(%q): %v", tmpDir, err)
	}

	code, stdout, stderr := runKeygen(t, []string{"-out", "keys"})

	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "cannot resolve") {
		t.Fatalf("stderr does not mention resolution failure: %q", stderr)
	}
}

// TestStderrLoggerInfo verifies the logger discards Info records: the
// command has nothing to say at Info level, and a noisy keymanager.New would
// clutter the operator's stderr with progress messages they did not ask for.
func TestStderrLoggerInfo(t *testing.T) {
	var buf bytes.Buffer
	l := stderrLogger{w: &buf}

	l.Info("anything %s", "at all")
	l.Info("more")

	if buf.Len() != 0 {
		t.Fatalf("Info wrote to stderr: %q", buf.String())
	}
}

// TestStderrLoggerWarn verifies the logger forwards Warn records verbatim
// with the authcore-keygen prefix. The keymanager uses Warn for non-fatal
// events (a leftover staging directory, a read-only mount refusing a
// metadata refresh); those messages must reach the operator.
func TestStderrLoggerWarn(t *testing.T) {
	var buf bytes.Buffer
	l := stderrLogger{w: &buf}

	l.Warn("something went wrong: %d", 42)

	got := buf.String()
	want := "authcore-keygen: something went wrong: 42\n"
	if got != want {
		t.Fatalf("Warn wrote %q, want %q", got, want)
	}
}
