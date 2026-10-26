package refusals_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/refusals"
)

func TestIncompleteLoad_ListsPresentAndMissing(t *testing.T) {
	cases := []struct {
		present, missing []string
		want             string
	}{
		{nil, nil, "present {none}, missing {none}"},
		{[]string{"a"}, []string{"b"}, "present {a}, missing {b}"},
		{[]string{"a", "b"}, []string{"c"}, "present {a, b}, missing {c}"},
		{[]string{"a"}, []string{"b", "c"}, "present {a}, missing {b, c}"},
	}
	for _, c := range cases {
		err := refusals.IncompleteLoad("/keys", c.present, c.missing)
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("IncompleteLoad(%v, %v) = %v, want it to contain %q", c.present, c.missing, err, c.want)
		}
	}
}

func TestWaitTimeout_ListsWhatIsOnDisk(t *testing.T) {
	names := layout.KeyFileNames()
	cases := []struct {
		name    string
		present int
		want    string
	}{
		{"nothing", 0, "present {none}, missing {" + strings.Join(names, ", ") + "}"},
		{"one file", 1, "present {" + names[0] + "}, missing {" + names[1] + ", " + names[2] + "}"},
		{"two files", 2, "present {" + names[0] + ", " + names[1] + "}, missing {" + names[2] + "}"},
		{"all three", 3, "present {" + strings.Join(names, ", ") + "}, missing {none}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range names[:c.present] {
				if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := refusals.WaitTimeout(dir)
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("WaitTimeout = %v\nwant it to contain %q", err, c.want)
			}
		})
	}
}
