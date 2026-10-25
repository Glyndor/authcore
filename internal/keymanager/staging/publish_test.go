package staging

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

func posixOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hard links and Unix modes require POSIX semantics")
	}
}

func stagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestPublish_writesTheThreeFilesAndHandsBackTheSameKeys(t *testing.T) {
	posixOnly(t)
	dir := t.TempDir()

	priv, pub, secret, err := Publish(dir, silentLog{})
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
	if left := stagingDirs(t, dir); len(left) != 0 {
		t.Errorf("staging directories left after a clean publish: %v", left)
	}
}

func TestPublish_twoRunsNeverShareKeys(t *testing.T) {
	a, _, _, err := Publish(t.TempDir(), silentLog{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := Publish(t.TempDir(), silentLog{})
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
	withFaultAt(t, func(p string) error {
		if p == "staged" {
			return sentinel
		}
		return nil
	})

	if _, _, _, err := Publish(dir, silentLog{}); !errors.Is(err, sentinel) {
		t.Fatalf("Publish = %v, want the sentinel", err)
	}
	if got := stagingDirs(t, dir); len(got) != 1 {
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
	posixOnly(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("winner"), 0600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := Publish(dir, silentLog{})
	if !errors.Is(err, ErrWaitAndLoad) {
		t.Fatalf("Publish = %v, want ErrWaitAndLoad", err)
	}
	if left := stagingDirs(t, dir); len(left) != 0 {
		t.Errorf("the loser left its staging directory behind: %v", left)
	}
	got, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil || string(got) != "winner" {
		t.Errorf("the winner's key was touched: %q, %v", got, err)
	}
}

func TestSymlinkPreflight(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	empty := t.TempDir()
	if err := SymlinkPreflight(empty); err != nil {
		t.Fatalf("an empty directory is not a symlink: %v", err)
	}

	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			err := SymlinkPreflight(dir)
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("SymlinkPreflight = %v, want a refusal naming the symlink", err)
			}
		})
	}
}

// Lstat failing for a reason other than "absent" is refused too: the slot
// cannot be shown to be empty.
func TestSymlinkPreflight_unclassifiableSlotIsRefused(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// dir/file/<name>: Lstat answers ENOTDIR, not ENOENT.
	if err := SymlinkPreflight(notADir); err == nil {
		t.Fatal("a path below a regular file must not pass the preflight")
	}
}

func TestStagingDirName_isHiddenPrefixedAndRandom(t *testing.T) {
	a, err := stagingDirName()
	if err != nil {
		t.Fatal(err)
	}
	b, err := stagingDirName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, layout.StagingPrefix) || len(a) != len(layout.StagingPrefix)+16 {
		t.Errorf("name %q does not carry the prefix and 16 hex characters", a)
	}
	if a == b {
		t.Error("two staging names collided")
	}
}

func TestCreateStagingSet_returnsMatchingKeysAndModes(t *testing.T) {
	dir := t.TempDir()
	staging, priv, pub, secret, err := createStagingSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) || len(secret) != layout.RefreshSecretLen {
		t.Fatal("createStagingSet returned inconsistent material")
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(staging, name)); err != nil {
			t.Errorf("%s was not staged: %v", name, err)
		}
	}
}
