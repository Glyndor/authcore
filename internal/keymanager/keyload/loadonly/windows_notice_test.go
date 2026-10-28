package loadonly_test

import (
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func TestWindowsNoticeLoadOnlyFirstAndThenBootstrap(t *testing.T) {
	previous := seams.GOOS
	seams.GOOS = "linux"
	t.Cleanup(func() { seams.GOOS = previous })
	dir := t.TempDir()
	if _, err := New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, dir)
	seams.GOOS = "windows"
	log := &bootstraptest.Recorder{}
	for i := 0; i < 2; i++ {
		if _, err := Load(dir, log); err != nil {
			t.Fatal(err)
		}
	}
	assertBytesUnchanged(t, dir, before)
	if got := log.CountWarns("Windows does not enforce Unix mode bits"); got != 1 {
		t.Fatalf("load-only Windows notices = %d, want 1", got)
	}
	if _, err := New(dir, log); err != nil {
		t.Fatal(err)
	}
	if got := log.CountWarns("Windows does not enforce Unix mode bits"); got != 1 {
		t.Fatalf("bootstrap repeated load-only notice: %d", got)
	}
}

func TestWindowsNoticeAbsentOnUnixLoadOnly(t *testing.T) {
	previous := seams.GOOS
	seams.GOOS = "linux"
	t.Cleanup(func() { seams.GOOS = previous })
	dir := t.TempDir()
	if _, err := New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatal(err)
	}
	log := &bootstraptest.Recorder{}
	if _, err := Load(dir, log); err != nil {
		t.Fatal(err)
	}
	if got := log.CountWarns("Windows does not enforce"); got != 0 {
		t.Fatalf("Unix load emitted %d Windows notices", got)
	}
}
