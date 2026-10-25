package createset

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

// midwayName is the staging directory name the tests below pin.
const midwayName = layout.StagingPrefix + "0001020304050607"

// readerFunc adapts a function to io.Reader.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// pinNameAndHookKeyGeneration makes the staging name deterministic and
// replaces the CSPRNG reader the key pair is drawn from with onRead. Create
// reads from it after the staging directory exists and before any file is
// written, which is the only place a test can break the directory from the
// inside. The reader still returns real randomness unless onRead fails.
func pinNameAndHookKeyGeneration(t *testing.T, onRead func() error) {
	t.Helper()
	prevRead, prevReader := randRead, rand.Reader
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	}
	rand.Reader = readerFunc(func(p []byte) (int, error) {
		if err := onRead(); err != nil {
			return 0, err
		}
		return io.ReadFull(prevReader, p)
	})
	t.Cleanup(func() { randRead, rand.Reader = prevRead, prevReader })
}

func TestCreate_keyGenerationFailureLeavesNoStaging(t *testing.T) {
	dir := t.TempDir()
	pinNameAndHookKeyGeneration(t, func() error { return errors.New("entropy offline") })

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "generate Ed25519 key pair") {
		t.Fatalf("Create = %v, want the key generation failure", err)
	}
	if left := stagingtest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("staging directories left after a failed Create: %v", left)
	}
}

// A file already sitting at one of the three names makes the exclusive create
// fail; the half-written staging directory is removed.
func TestCreate_stagedFileWriteFailureRemovesTheStaging(t *testing.T) {
	dir := t.TempDir()
	pinNameAndHookKeyGeneration(t, func() error {
		return os.WriteFile(filepath.Join(dir, midwayName, layout.FilePrivateKey), []byte("squatter"), 0600)
	})

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "stage") {
		t.Fatalf("Create = %v, want the staged-file failure", err)
	}
	if left := stagingtest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("staging directories left after a failed Create: %v", left)
	}
}

// A staging directory that can be written and searched but not read cannot be
// opened for fsync; the failure is returned instead of being swallowed.
func TestCreate_syncFailureOnTheStagingDirectoryIsReturned(t *testing.T) {
	stagingtest.PosixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	dir := t.TempDir()
	staging := filepath.Join(dir, midwayName)
	t.Cleanup(func() { _ = os.Chmod(staging, 0700) })
	pinNameAndHookKeyGeneration(t, func() error { return os.Chmod(staging, 0300) })

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "sync staging directory") {
		t.Fatalf("Create = %v, want the staging-directory sync failure", err)
	}
}
