package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

// TestRefusesASymlinkAsOut covers a -out that is a link: the tool names the
// link and writes nothing through it.
func TestRefusesASymlinkAsOut(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "keys")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	code, stdout, stderr := runKeygen(t, []string{"-out", link})

	if code != exitFailure || stdout != "" {
		t.Fatalf("exit code %d, stdout %q; want %d and nothing", code, stdout, exitFailure)
	}
	if !strings.Contains(stderr, "symbolic link") {
		t.Errorf("stderr does not name the link: %q", stderr)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("the link target received %v", entries)
	}
}
