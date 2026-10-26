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

// TestWritesANewKeySet covers the happy path: a fresh directory receives the key
// set, stdout holds exactly the two lines the contract promises, and key
// material stays off the wire. Every successful run also emits one
// fresh-generation Warn on stderr, which is the signal operators wire into
// monitoring when a deployment has just generated new keys.
func TestWritesANewKeySet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	code, stdout, stderr := runKeygen(t, []string{"-out", dir})

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "generating a fresh key set") {
		t.Fatalf("stderr = %q, want the fresh-generation Warn", stderr)
	}
	if got := strings.Count(stderr, "generating a fresh key set"); got != 1 {
		t.Fatalf("fresh-generation Warn appeared %d times, want exactly 1; stderr=%q",
			got, stderr)
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
