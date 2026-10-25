package staging

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

func TestPublish_writesTheThreeFilesAndHandsBackTheSameKeys(t *testing.T) {
	stagingtest.PosixOnly(t)
	dir := t.TempDir()

	priv, pub, secret, err := Publish(dir, stagingtest.SilentLog{})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := material.Validate(priv, pub, secret); err != nil {
		t.Fatalf("Publish returned unusable material: %v", err)
	}

	for name, wantMode := range map[string]os.FileMode{
		layout.FilePrivateKey:    0600,
		layout.FilePublicKey:     0644,
		layout.FileRefreshSecret: 0600,
	} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != wantMode {
			t.Errorf("%s mode = %04o, want %04o", name, fi.Mode().Perm(), wantMode)
		}
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, err := pemcodec.DecodeEd25519PrivatePEM(onDisk, "published")
	if err != nil || !gotPriv.Equal(priv) {
		t.Errorf("the published private key is not the returned one: %v", err)
	}
	hexSecret, err := os.ReadFile(filepath.Join(dir, layout.FileRefreshSecret)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(hexSecret)); got != hex.EncodeToString(secret) {
		t.Errorf("the published refresh secret differs from the returned one")
	}
	if left := stagingtest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("staging directories left after a clean publish: %v", left)
	}
}

func TestPublish_twoRunsNeverShareKeys(t *testing.T) {
	a, _, _, err := Publish(t.TempDir(), stagingtest.SilentLog{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := Publish(t.TempDir(), stagingtest.SilentLog{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two publishes produced the same private key")
	}
}

// A fault at "staged" aborts without cleaning up, exactly as a crash between
// writing the staging directory and linking from it would.
func TestPublish_faultAfterStagingLeavesTheStagingDirectory(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("crash after staging")
	stagingtest.WithFaultAt(t, func(p string) error {
		if p == "staged" {
			return sentinel
		}
		return nil
	})

	if _, _, _, err := Publish(dir, stagingtest.SilentLog{}); !errors.Is(err, sentinel) {
		t.Fatalf("Publish = %v, want the sentinel", err)
	}
	if got := stagingtest.StagingDirs(t, dir); len(got) != 1 {
		t.Fatalf("staging directories after the fault: %v, want exactly one left as recovery material", got)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was published despite the crash: %v", name, err)
		}
	}
}

// Losing the race for the private link is reported as ErrWaitAndLoad, and the
// loser's own staging directory is removed so only the winner's remains.
func TestPublish_losingThePrivateLinkRaceAsksTheCallerToWait(t *testing.T) {
	stagingtest.PosixOnly(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("winner"), 0600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := Publish(dir, stagingtest.SilentLog{})
	if !errors.Is(err, ErrWaitAndLoad) {
		t.Fatalf("Publish = %v, want ErrWaitAndLoad", err)
	}
	if left := stagingtest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("the loser left its staging directory behind: %v", left)
	}
	got, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil || string(got) != "winner" {
		t.Errorf("the winner's key was touched: %q, %v", got, err)
	}
}

func TestPublish_missingKeysDirectoryIsReported(t *testing.T) {
	_, _, _, err := Publish(filepath.Join(t.TempDir(), "absent"), stagingtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "create staging directory") {
		t.Fatalf("Publish = %v, want the create-staging-directory failure", err)
	}
}
