package bootstrap_test

import (
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func TestWindowsNoticeOnCreationAndExistingLoad(t *testing.T) {
	previous := seams.GOOS
	t.Cleanup(func() { seams.GOOS = previous })
	for _, existing := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "keys")
		seams.GOOS = "linux"
		if existing {
			if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
				t.Fatal(err)
			}
		}
		seams.GOOS = "windows"
		log := &bootstraptest.Recorder{}
		for i := 0; i < 2; i++ {
			if _, err := bootstraptest.New(dir, log); err != nil {
				t.Fatal(err)
			}
		}
		if got := log.CountWarns("Windows does not enforce Unix mode bits"); got != 1 {
			t.Errorf("existing=%v: Windows notices = %d, want 1", existing, got)
		}
		if _, err := bootstraptest.Load(dir, log); err != nil {
			t.Fatal(err)
		}
		if got := log.CountWarns("Windows does not enforce Unix mode bits"); got != 1 {
			t.Errorf("load-only repeated the notice: %d", got)
		}
	}
}

func TestWindowsNoticeAbsentOnUnixBootstrap(t *testing.T) {
	previous := seams.GOOS
	seams.GOOS = "linux"
	t.Cleanup(func() { seams.GOOS = previous })
	dir := t.TempDir()
	log := &bootstraptest.Recorder{}
	for i := 0; i < 2; i++ {
		if _, err := bootstraptest.New(dir, log); err != nil {
			t.Fatal(err)
		}
	}
	if got := log.CountWarns("Windows does not enforce"); got != 0 {
		t.Fatalf("Unix bootstrap emitted %d Windows notices: %q", got, log.Warns)
	}
}
