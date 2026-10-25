package recoverytest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// failingTB turns Fatal into a panic the test can catch, so the failure
// branches of the helpers are exercised without failing this test.
type failingTB struct {
	testing.TB
}

func (failingTB) Helper() {}
func (failingTB) Fatal(args ...any) {
	panic(fmt.Sprint(args...))
}
func (failingTB) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

func mustFatal(t *testing.T, name string, fn func(tb testing.TB)) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not fail on a bad input", name)
		}
	}()
	fn(failingTB{t})
}

func TestHelpersFailTheTestOnBadInput(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	mustFatal(t, "MustSeed", func(tb testing.TB) { recoverytest.MustSeed(tb, filepath.Join(blocker, "keys")) })
	mustFatal(t, "CopyFile (read)", func(tb testing.TB) { recoverytest.CopyFile(tb, missing, blocker) })
	mustFatal(t, "CopyFile (write)", func(tb testing.TB) { recoverytest.CopyFile(tb, src, missing+"/dst") })
	mustFatal(t, "StagingFrom (mkdir)", func(tb testing.TB) { recoverytest.StagingFrom(tb, blocker, "x", src) })
	mustFatal(t, "StagingFrom (copy)", func(tb testing.TB) { recoverytest.StagingFrom(tb, t.TempDir(), "x", missing) })
	mustFatal(t, "Complete", func(tb testing.TB) { recoverytest.Complete(tb, blocker) })
}

func TestSeedKeysReportsAnUnwritableKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.FilePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	if err := recoverytest.SeedKeys(dir); err == nil {
		t.Fatal("SeedKeys over a directory named like a key file returned nil")
	}
}
