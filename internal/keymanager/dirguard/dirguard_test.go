//go:build unix

package dirguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrimTrailing(t *testing.T) {
	for in, want := range map[string]string{
		"keys":        "keys",
		"keys/":       "keys",
		"keys//":      "keys",
		"keys/.":      "keys",
		"keys/./":     "keys",
		"keys/./.":    "keys",
		"a/b/.":       "a/b",
		"a/..":        "a/..",
		"a/../":       "a/..",
		".":           ".",
		"./":          "./",
		"/":           "/",
		"/.":          "/",
		"/keys/.hide": "/keys/.hide",
	} {
		if got := trimTrailing(in); got != want {
			t.Errorf("trimTrailing(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRefuse(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "parent")
	if err := os.Symlink(root, parentLink); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		path    string
		refused bool
	}{
		"directory":         {real, false},
		"absent":            {filepath.Join(root, "absent"), false},
		"link":              {link, true},
		"link with slash":   {link + "/", true},
		"link with dot":     {link + "/.", true},
		"link in parent":    {filepath.Join(parentLink, "real"), false},
		"empty":             {"", false},
		"current directory": {".", false},
	} {
		t.Run(name, func(t *testing.T) {
			err := Refuse(tc.path)
			if (err != nil) != tc.refused {
				t.Fatalf("Refuse(%q) = %v, refused want %v", tc.path, err, tc.refused)
			}
			if err != nil && !strings.Contains(err.Error(), "symbolic link") {
				t.Errorf("the refusal does not name the cause: %v", err)
			}
		})
	}
}
