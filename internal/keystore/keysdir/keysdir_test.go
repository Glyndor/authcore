package keysdir_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keystore/keysdir"
)

func TestCheckDir(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := keysdir.CheckDir(filepath.Join(base, "new", "nested")); err != nil {
		t.Errorf("CheckDir on a creatable path = %v, want nil", err)
	}
	err := keysdir.CheckDir(filepath.Join(file, "under"))
	if err == nil || !strings.Contains(err.Error(), "cannot create keys directory") {
		t.Errorf("CheckDir below a regular file = %v, want a create failure", err)
	}
}

func TestCheckLoadOnlyDir(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, dir, want string
	}{
		{"missing", filepath.Join(base, "missing"), "does not exist"},
		{"regular file", file, "not a directory"},
		{"stat fails otherwise", filepath.Join(file, "under"), "inspect key directory"},
	}
	for _, c := range cases {
		err := keysdir.CheckLoadOnlyDir(c.dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: CheckLoadOnlyDir = %v, want error containing %q", c.name, err, c.want)
		}
	}
	if err := keysdir.CheckLoadOnlyDir(base); err != nil {
		t.Errorf("CheckLoadOnlyDir on a directory = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(base, "missing")); err == nil {
		t.Error("CheckLoadOnlyDir created the directory it was asked to inspect")
	}
}

func TestChecksRefuseASymlinkedKeysDir(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for name, check := range map[string]func(string) error{
		"CheckDir": keysdir.CheckDir, "CheckLoadOnlyDir": keysdir.CheckLoadOnlyDir,
	} {
		if err := check(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("%s on a symlink = %v, want the symbolic link refusal", name, err)
		}
	}
	if fi, err := os.Stat(real); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("the link target was changed: %v %v", fi, err)
	}
}
