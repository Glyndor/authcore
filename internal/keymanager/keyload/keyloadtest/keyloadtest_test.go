package keyloadtest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestWriteSetDropsTheThreeFiles(t *testing.T) {
	dir := t.TempDir()
	set := keyloadtest.WriteSet(t, dir)
	if len(set.Priv) == 0 || len(set.Pub) == 0 || len(set.Secret) != layout.RefreshSecretLen {
		t.Fatal("WriteSet returned incomplete material")
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRecorderKeepsFormattedWarningsOnly(t *testing.T) {
	var r keyloadtest.Recorder
	r.Info("ignored")
	r.Warn("one %d", 1)
	r.Warn("two")
	if len(r.Warnings) != 2 || r.Warnings[0] != "one 1" || r.Warnings[1] != "two" {
		t.Fatalf("Warnings = %q", r.Warnings)
	}
	keyloadtest.SilentLog{}.Info("x")
	keyloadtest.SilentLog{}.Warn("x")
}

// failingTB turns Fatal into a panic the test can catch, so the failure
// branch of Put is exercised without failing this test.
type failingTB struct{ testing.TB }

func (failingTB) Helper()           {}
func (failingTB) Fatal(args ...any) { panic(fmt.Sprint(args...)) }

func TestPutFailsTheTestWhenTheFileCannotBeWritten(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Put did not fail for a directory that does not exist")
		}
	}()
	keyloadtest.Put(failingTB{t}, filepath.Join(t.TempDir(), "absent"), "x", nil, 0600)
}
