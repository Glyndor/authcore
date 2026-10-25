package keystore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keystore"
)

func TestCheckDir(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := keystore.CheckDir(filepath.Join(base, "new", "nested")); err != nil {
		t.Errorf("CheckDir on a creatable path = %v, want nil", err)
	}
	err := keystore.CheckDir(filepath.Join(file, "under"))
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
		err := keystore.CheckLoadOnlyDir(c.dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: CheckLoadOnlyDir = %v, want error containing %q", c.name, err, c.want)
		}
	}
	if err := keystore.CheckLoadOnlyDir(base); err != nil {
		t.Errorf("CheckLoadOnlyDir on a directory = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(base, "missing")); err == nil {
		t.Error("CheckLoadOnlyDir created the directory it was asked to inspect")
	}
}
