package fsguard_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
)

func TestCreateExclusive_RefusesAnExistingEntryAndKeepsItIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ed25519_private.pem")
	if err := os.WriteFile(path, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := fsguard.CreateExclusive(path, []byte("secret"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "refusing to write") {
		t.Fatalf("err = %v, want the refusal to write over an existing entry", err)
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Errorf("err = %v, want it to wrap fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "planted" {
		t.Errorf("existing file now holds %q", got)
	}
}

// A destination that cannot be created for another reason is an ordinary
// error: it must not be reported as "something already exists there".
func TestCreateExclusive_ReportsOtherFailuresAsThemselves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "key")

	err := fsguard.CreateExclusive(path, []byte("secret"), 0o600)
	if err == nil {
		t.Fatal("CreateExclusive succeeded in a directory that does not exist")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
	if strings.Contains(err.Error(), "refusing to write") {
		t.Errorf("err = %v, wrongly claims the destination already existed", err)
	}
}
