package linkkeys_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/createset"
	"github.com/Glyndor/authcore/internal/keymanager/staging/linkkeys"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

type warnings struct {
	mu    sync.Mutex
	lines []string
}

func (*warnings) Info(string, ...any) {}

func (w *warnings) Warn(msg string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, fmt.Sprintf(msg, args...))
}

func staged(t *testing.T) (dir, staging string) {
	t.Helper()
	stagingtest.PosixOnly(t)
	dir = t.TempDir()
	staging, _, _, _, err := createset.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, staging
}

func has(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The private key link is the commit point. When it landed although the call
// reported an error, a later failure must keep the staging directory: it holds
// the other two files a restart needs to finish the set.
func TestLink_KeepsStagingWhenALandedPrivateLinkIsFollowedByAFailure(t *testing.T) {
	dir, staging := staged(t)
	stagingtest.WithLinkFile(t, func(src, dst string) error {
		switch filepath.Base(dst) {
		case layout.FilePrivateKey:
			if err := os.Link(src, dst); err != nil {
				return err
			}
			return syscall.EIO
		default:
			return syscall.EPERM
		}
	})
	var log warnings

	err := linkkeys.Link(dir, staging, &log)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("Link = %v, want the failure of the public key link", err)
	}
	if !strings.Contains(err.Error(), "kept as recovery material") {
		t.Errorf("err = %v, want it to say the staging directory was kept", err)
	}
	if !has(filepath.Join(staging, layout.FilePrivateKey)) {
		t.Error("the staging directory was removed although the private key was already published")
	}
	if !has(filepath.Join(dir, layout.FilePrivateKey)) || has(filepath.Join(dir, layout.FilePublicKey)) {
		t.Error("the key directory does not hold exactly the private key")
	}
}

func TestLink_DropsStagingWhenNothingWasPublished(t *testing.T) {
	dir, staging := staged(t)
	stagingtest.WithLinkFile(t, func(string, string) error { return syscall.EPERM })
	var log warnings

	err := linkkeys.Link(dir, staging, &log)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("Link = %v, want the link failure", err)
	}
	if strings.Contains(err.Error(), "kept as recovery material") {
		t.Errorf("err = %v, claims a staging directory was kept", err)
	}
	if has(staging) {
		t.Error("the staging directory of an unpublished set was left behind")
	}
}

func TestLink_SuccessLogsNothing(t *testing.T) {
	dir, staging := staged(t)
	var log warnings

	if err := linkkeys.Link(dir, staging, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.lines) != 0 {
		t.Errorf("warnings on a clean publish: %q", log.lines)
	}
	if has(staging) {
		t.Error("the staging directory was not removed after publishing")
	}
}

// A staging directory that cannot be removed is reported, and the publish
// still counts as done.
func TestLink_WarnsWhenTheStagingDirectoryCannotBeRemoved(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes directories regardless of their mode")
	}
	dir, staging := staged(t)
	stuck := filepath.Join(staging, "stuck")
	stagingtest.WithLinkFile(t, func(src, dst string) error {
		if err := os.Link(src, dst); err != nil {
			return err
		}
		if filepath.Base(dst) == layout.FileRefreshSecret {
			if err := os.MkdirAll(stuck, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stuck, "f"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stuck, 0); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })
	var log warnings

	if err := linkkeys.Link(dir, staging, &log); err != nil {
		t.Fatalf("Link = %v, want success: the keys are published", err)
	}
	if len(log.lines) != 1 || !strings.Contains(log.lines[0], "could not remove staging directory") {
		t.Fatalf("warnings = %q, want the removal warning", log.lines)
	}
}

// A fault at a publish point aborts the transaction where it stands, as a
// crash would: what was linked stays linked and the staging directory stays.
func TestLink_ReturnsAFaultAtAPublishPointWithoutCleaning(t *testing.T) {
	dir, staging := staged(t)
	crash := errors.New("simulated crash")
	stagingtest.WithFaultAt(t, func(point string) error {
		if point == "published-private" {
			return crash
		}
		return nil
	})
	var log warnings

	if err := linkkeys.Link(dir, staging, &log); !errors.Is(err, crash) {
		t.Fatalf("Link = %v, want the injected fault", err)
	}
	if !has(filepath.Join(dir, layout.FilePrivateKey)) || has(filepath.Join(dir, layout.FilePublicKey)) {
		t.Error("the directory does not hold exactly the private key")
	}
	if !has(staging) {
		t.Error("the staging directory was removed by an aborted publish")
	}
}

// Losing the race to another initialiser drops our own staging directory; a
// directory that cannot be dropped is reported, and a clean drop is silent.
func TestLink_LostRaceReportsAStagingDirectoryItCannotDrop(t *testing.T) {
	for _, stuckDir := range []bool{false, true} {
		name := "clean"
		if stuckDir {
			name = "stuck"
		}
		t.Run(name, func(t *testing.T) {
			if stuckDir && os.Getuid() == 0 {
				t.Skip("root removes directories regardless of their mode")
			}
			dir, staging := staged(t)
			if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("winner"), 0o600); err != nil {
				t.Fatal(err)
			}
			if stuckDir {
				// A non-empty directory in place of a key file cannot be removed.
				if err := os.Remove(filepath.Join(staging, layout.FilePublicKey)); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(staging, layout.FilePublicKey), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey, "f"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var log warnings

			err := linkkeys.Link(dir, staging, &log)
			if !errors.Is(err, linkkeys.ErrWaitAndLoad) {
				t.Fatalf("Link = %v, want ErrWaitAndLoad", err)
			}
			if stuckDir != (len(log.lines) == 1) || len(log.lines) > 1 {
				t.Fatalf("warnings = %q (stuck=%v)", log.lines, stuckDir)
			}
		})
	}
}
