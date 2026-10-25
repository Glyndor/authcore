package generate_test

import (
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
)

// A publisher that died after linking the private key left a staging directory
// holding all three files; Open finishes the publish from it and loads.
func TestOpen_recoversAnInterruptedPublish(t *testing.T) {
	bootstraptest.PosixOnly(t)
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	sentinel := errors.New("crash after the private key was linked")
	bootstraptest.WithFault(t, func(p string) error {
		if p == "published-private" {
			return sentinel
		}
		return nil
	})
	if _, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{}); !errors.Is(err, sentinel) {
		t.Fatalf("first Open = %v, want the sentinel", err)
	}
	bootstraptest.WithFault(t, func(string) error { return nil })

	if _, err := os.Stat(filepath.Join(dir, layout.FilePublicKey)); !os.IsNotExist(err) {
		t.Fatalf("the crash left a public key behind: %v", err)
	}
	log := &bootstraptest.Recorder{}
	priv, pub, secret := bootstraptest.OpenOK(t, dir, log)
	if err := material.Validate(priv, pub, secret); err != nil {
		t.Fatalf("recovered material: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after recovery: %v", name, err)
		}
	}
	if !log.Warned("staging directory") {
		t.Errorf("the staging directory that was left behind was not reported: %q", log.Warns)
	}
}

func TestOpen_faultsAbortLikeACrash(t *testing.T) {
	for _, point := range []string{"staged", "published-private", "published-public", "published-secret", "metadata-written"} {
		t.Run(point, func(t *testing.T) {
			bootstraptest.PosixOnly(t)
			sentinel := errors.New("crash at " + point)
			bootstraptest.WithFault(t, func(p string) error {
				if p == point {
					return sentinel
				}
				return nil
			})
			if _, _, _, err := bootstrap.Open(t.TempDir(), &bootstraptest.Recorder{}); !errors.Is(err, sentinel) {
				t.Fatalf("Open = %v, want the sentinel", err)
			}
		})
	}
}

// The loser of the race for the private link waits for the winner's set and
// loads it; it never generates a second set.
func TestOpen_loserOfThePublishRaceLoadsTheWinnersKeys(t *testing.T) {
	bootstraptest.PosixOnly(t)
	base := t.TempDir()
	winnerDir := filepath.Join(base, "winner")
	winnerPriv, winnerPub, _ := bootstraptest.OpenOK(t, winnerDir, &bootstraptest.Recorder{})

	dir := filepath.Join(base, "keys")
	var once sync.Once
	bootstraptest.WithLinkFile(t, func(oldpath, newpath string) error {
		var err error
		once.Do(func() {
			for _, name := range layout.KeyFileNames() {
				if werr := os.WriteFile(filepath.Join(dir, name), bootstraptest.ReadFile(t, winnerDir, name), 0600); werr != nil {
					err = werr
					return
				}
			}
			err = fs.ErrExist
		})
		if err != nil {
			return err
		}
		return os.Link(oldpath, newpath)
	})

	priv, pub, _ := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if !priv.Equal(winnerPriv) || !pub.Equal(winnerPub) {
		t.Fatal("the loser generated its own keys instead of loading the winner's")
	}
}

func TestOpen_filesystemWithoutHardLinksIsRefused(t *testing.T) {
	bootstraptest.PosixOnly(t)
	bootstraptest.WithLinkFile(t, func(string, string) error { return errors.New("operation not supported") })
	dir := t.TempDir()
	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "does not support hard links") {
		t.Fatalf("Open = %v, want the no-hard-links refusal", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, serr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(serr) {
			t.Errorf("%s was published on a filesystem that cannot link: %v", name, serr)
		}
	}
}

// A parent with search but no read permission cannot be opened for the fsync
// before the first publish. Nothing needs to read it, so Open warns and
// publishes.
func TestOpen_warnsWhenTheParentCannotBeSynced(t *testing.T) {
	bootstraptest.NotRoot(t)
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	dir := filepath.Join(parent, "keys")
	log := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, log)
	if !log.Warned("could not sync the parent") {
		t.Errorf("no warning about the parent sync; warnings: %q", log.Warns)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not published: %v", name, err)
		}
	}
}

func TestOpen_concurrentInitialisersAgree(t *testing.T) {
	bootstraptest.PosixOnly(t)
	dir := filepath.Join(t.TempDir(), "keys")
	const n = 8
	type result struct {
		priv ed25519.PrivateKey
		err  error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			priv, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
			results[i] = result{priv, err}
		}()
	}
	close(start)
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("initialiser %d: %v", i, r.err)
		}
		if !r.priv.Equal(results[0].priv) {
			t.Fatalf("initialiser %d holds a different private key: two sets were generated", i)
		}
	}
}
