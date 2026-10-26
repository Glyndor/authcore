package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// provision writes a complete key set into a fresh directory, as the keygen
// step of the recipe does, and returns the directory and the loaded keys.
func provision(t *testing.T) (string, authcore.Keys) {
	t.Helper()
	dir := t.TempDir()
	cfg := authcore.Config{KeysDir: dir}
	auth, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dir, auth.Keys()
}

// snapshot maps every file under dir to its mode and content.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		content := ""
		if !d.IsDir() {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			content = string(raw)
		}
		out[path] = info.Mode().String() + "|" + info.ModTime().String() + "|" + content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestLoadReportsTheKeyIDAndNothingSecret checks the one line the recipe
// compares across replicas, and that nothing else leaves the process.
func TestLoadReportsTheKeyIDAndNothingSecret(t *testing.T) {
	dir, keys := provision(t)
	var stdout, stderr bytes.Buffer

	if code := load(dir, true, &stdout, &stderr); code != 0 || stdout.Len() != 0 {
		t.Fatalf("-check: code %d, stdout %q", code, stdout.String())
	}
	if code := load(dir, false, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	if want := "key id " + keys.KeyID() + "\n"; stdout.String() != want {
		t.Errorf("stdout %q, want %q", stdout.String(), want)
	}

	all := stdout.String() + stderr.String()
	for name, secret := range map[string][]byte{"private key": keys.PrivateKey(), "refresh secret": keys.RefreshSecret()} {
		for _, form := range []string{hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret)} {
			if strings.Contains(all, form) {
				t.Errorf("the %s is in the output", name)
			}
		}
	}
}

// TestLoadFailsClosedAndWritesNothing covers the directories a replica can
// start with: none, empty, and one missing a file. None may start, and none may
// be given a fresh key set, which would split the replicas onto different keys.
func TestLoadFailsClosedAndWritesNothing(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		var stdout, stderr bytes.Buffer
		if code := load(dir, false, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "probe:") {
			t.Errorf("code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Errorf("the empty directory was filled: %d entries", len(entries))
		}
	})

	t.Run("directory missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "absent")
		var stdout, stderr bytes.Buffer
		if code := load(dir, false, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Errorf("code %d, stdout %q", code, stdout.String())
		}
		if _, err := os.Stat(dir); err == nil {
			t.Error("the missing directory was created")
		}
	})

	t.Run("variable unset", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var stdout, stderr bytes.Buffer
		if code := load("", false, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Errorf("code %d, stdout %q", code, stdout.String())
		}
		if entries, _ := os.ReadDir("."); len(entries) != 0 {
			t.Errorf("the working directory received %d entries", len(entries))
		}
	})

	t.Run("one file missing", func(t *testing.T) {
		dir, _ := provision(t)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.Contains(e.Name(), "refresh") || strings.Contains(e.Name(), "secret") {
				if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
		before := snapshot(t, dir)
		var stdout, stderr bytes.Buffer
		if code := load(dir, false, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Errorf("code %d, stdout %q", code, stdout.String())
		}
		if after := snapshot(t, dir); len(after) != len(before) {
			t.Errorf("the incomplete directory changed: %d entries before, %d after", len(before), len(after))
		}
	})
}

// TestLoadDoesNotTouchAReadOnlyVolume mounts the keys the way compose does,
// read-only, and checks the process neither fails nor changes anything.
func TestLoadDoesNotTouchAReadOnlyVolume(t *testing.T) {
	dir, _ := provision(t)
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o400)
		if d.IsDir() {
			mode = 0o500
		}
		return os.Chmod(path, mode)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	before := snapshot(t, dir)
	var stdout, stderr bytes.Buffer
	if code := load(dir, false, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
	after := snapshot(t, dir)
	if len(after) != len(before) {
		t.Fatalf("entries changed: %d before, %d after", len(before), len(after))
	}
	for path, state := range before {
		if after[path] != state {
			t.Errorf("%s changed", path)
		}
	}
}
