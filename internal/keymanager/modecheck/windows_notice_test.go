package modecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// noticePlatform sets the platform for one test and empties the registry of
// directories already warned about. The registry compares directories with
// SameFile, and a temporary directory can reuse the identity of one a previous
// test deleted, which made a later test think its directory had been seen.
func noticePlatform(t *testing.T, goos string) {
	t.Helper()
	previous := seams.GOOS
	seams.GOOS = goos
	resetNotices()
	t.Cleanup(func() {
		seams.GOOS = previous
		resetNotices()
	})
}

func resetNotices() {
	windowsNotices.Lock()
	windowsNotices.dirs = nil
	windowsNotices.Unlock()
}

func TestNeedsWindowsNotice(t *testing.T) {
	for _, tc := range []struct {
		goos string
		seen bool
		want bool
	}{
		{"windows", false, true},
		{"windows", true, false},
		{"linux", false, false},
		{"linux", true, false},
		{"darwin", false, false},
		{"darwin", true, false},
	} {
		if got := needsWindowsNotice(tc.goos, tc.seen); got != tc.want {
			t.Errorf("needsWindowsNotice(%q, %v) = %v, want %v", tc.goos, tc.seen, got, tc.want)
		}
	}
}

func TestWindowsNoticeOncePerDirectoryAndProcess(t *testing.T) {
	noticePlatform(t, "windows")
	dir := t.TempDir()
	first, second := &recorder{}, &recorder{}
	WarnWindowsDirectory(dir, first)
	WarnWindowsDirectory(dir+string(os.PathSeparator)+".", second)
	WarnWindowsDirectory(t.TempDir(), second)
	if len(first.warnings) != 1 || len(second.warnings) != 1 {
		t.Fatalf("warnings per logger = %q / %q, want one per directory", first.warnings, second.warnings)
	}
	for _, fragment := range []string{
		"Windows does not enforce Unix mode bits",
		"inherit ACLs from their parent directory",
		"operator must restrict the key directory ACLs",
		"only the service account can read it", dir,
	} {
		if !strings.Contains(first.warnings[0], fragment) {
			t.Errorf("notice %q lacks %q", first.warnings[0], fragment)
		}
	}
}

func TestWindowsNoticeRecognisesParentSymlink(t *testing.T) {
	noticePlatform(t, "windows")
	parent := t.TempDir()
	dir := filepath.Join(parent, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(parent, alias); err != nil {
		t.Skipf("parent symlink unavailable: %v", err)
	}
	log := &recorder{}
	WarnWindowsDirectory(dir, log)
	WarnWindowsDirectory(filepath.Join(alias, "keys"), log)
	if len(log.warnings) != 1 {
		t.Fatalf("parent alias repeated the notice: %q", log.warnings)
	}
}

func TestWindowsNoticeUnixDoesNotWarnOrConsumeNotice(t *testing.T) {
	dir := t.TempDir()
	log := &recorder{}
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		noticePlatform(t, goos)
		WarnWindowsDirectory(dir, log)
	}
	if len(log.warnings) != 0 {
		t.Fatalf("Unix acquired a new warning: %q", log.warnings)
	}
	noticePlatform(t, "windows")
	WarnWindowsDirectory(dir, log)
	if len(log.warnings) != 1 {
		t.Fatalf("Unix consumed the Windows notice: %q", log.warnings)
	}
}

func TestWindowsNoticeInvalidDirectoryIsSilent(t *testing.T) {
	noticePlatform(t, "windows")
	log := &recorder{}
	WarnWindowsDirectory(filepath.Join(t.TempDir(), "missing"), log)
	WarnWindowsDirectory(fileAt(t, 0600), log)
	if len(log.warnings) != 0 {
		t.Fatalf("invalid directory warned: %q", log.warnings)
	}
}

type concurrentNoticeLog struct {
	sync.Mutex
	warnings []string
}

func (*concurrentNoticeLog) Info(string, ...any) {}
func (l *concurrentNoticeLog) Warn(msg string, args ...any) {
	l.Lock()
	defer l.Unlock()
	l.warnings = append(l.warnings, fmt.Sprintf(msg, args...))
}

func TestWindowsNoticeConcurrentCalls(t *testing.T) {
	noticePlatform(t, "windows")
	dir := t.TempDir()
	log := &concurrentNoticeLog{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			WarnWindowsDirectory(dir, log)
		}()
	}
	wg.Wait()
	if len(log.warnings) != 1 {
		t.Fatalf("concurrent calls emitted %d warnings, want 1", len(log.warnings))
	}
}
