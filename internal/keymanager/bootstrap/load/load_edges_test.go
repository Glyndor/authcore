package load_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A faultAt return is a test-only signal: it aborts the load as a crash would,
// instead of being downgraded to the warning a real descriptor write failure
// gets.
func TestOpen_descriptorFaultAbortsTheLoad(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("crash while adopting the directory")
	bootstraptest.WithFault(t, func(p string) error {
		if p == "metadata-written" {
			return sentinel
		}
		return nil
	})
	if _, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{}); !errors.Is(err, sentinel) {
		t.Fatalf("Open = %v, want the sentinel", err)
	}
}

// A directory that can be written and searched but not read can load its keys
// and take a descriptor, but cannot be opened for fsync. That is a warning: the
// metadata is already written when possible, and the keys are loaded.
func TestOpen_unsyncableDirectoryStillLoads(t *testing.T) {
	bootstraptest.NotRoot(t)
	dir := t.TempDir()
	_, pub, _ := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	log := &bootstraptest.Recorder{}
	_, got, _ := bootstraptest.OpenOK(t, dir, log)
	if !got.Equal(pub) {
		t.Fatal("loaded different keys")
	}
	if !log.Warned("could not sync key directory") {
		t.Errorf("no warning about the directory sync; warnings: %q", log.Warns)
	}
}
