package bootstrap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
)

func TestOpen_generatesTheFilesWithTheirModes(t *testing.T) {
	bootstraptest.PosixOnly(t)
	dir := filepath.Join(t.TempDir(), "nested", "keys")
	priv, pub, secret := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})

	if err := material.Validate(priv, pub, secret); err != nil {
		t.Fatalf("Open returned unusable material: %v", err)
	}
	want := map[string]os.FileMode{
		layout.FilePrivateKey:    0600,
		layout.FilePublicKey:     0644,
		layout.FileRefreshSecret: 0600,
		layout.FileGitignore:     0600,
		layout.FileMetadata:      0600,
	}
	for name, mode := range want {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode = %04o, want %04o", name, fi.Mode().Perm(), mode)
		}
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != layout.DirMode {
		t.Errorf("key directory mode = %v, %v; want %04o", fi.Mode().Perm(), err, layout.DirMode)
	}
	if got := string(bootstraptest.ReadFile(t, dir, layout.FileGitignore)); got != layout.GitignoreContent {
		t.Errorf(".gitignore = %q", got)
	}
}

func TestOpen_recordsTheLayoutAndWarnsOnceOnFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	log := &bootstraptest.Recorder{}
	_, pub, _ := bootstraptest.OpenOK(t, dir, log)

	if n := log.CountWarns("generating a fresh key set"); n != 1 {
		t.Errorf("fresh-generation warnings = %d, want 1", n)
	}
	meta, err := metadata.Read(dir)
	if err != nil || meta == nil || meta.KeyID != material.KeyID(pub) || meta.Format != metadata.CurrentFormat {
		t.Fatalf("metadata after Open = %+v, %v", meta, err)
	}

	again := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, again)
	if again.Warned("generating a fresh key set") {
		t.Error("loading an existing set warned about generating a fresh one")
	}
}

func TestOpen_secondRunLoadsTheSameKeys(t *testing.T) {
	dir := t.TempDir()
	priv1, pub1, secret1 := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	priv2, pub2, secret2 := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if !priv1.Equal(priv2) || !pub1.Equal(pub2) || string(secret1) != string(secret2) {
		t.Fatal("a second Open produced different keys")
	}
}

func TestOpen_twoDirectoriesNeverShareKeys(t *testing.T) {
	a, _, _ := bootstraptest.OpenOK(t, t.TempDir(), &bootstraptest.Recorder{})
	b, _, _ := bootstraptest.OpenOK(t, t.TempDir(), &bootstraptest.Recorder{})
	if a.Equal(b) {
		t.Fatal("two directories got the same private key")
	}
}

func TestOpen_tightensButNeverLoosensTheDirectory(t *testing.T) {
	bootstraptest.NotRoot(t)
	for _, tc := range []struct{ before, after os.FileMode }{
		{0o755, 0o700},
		{0o750, 0o700},
		{0o500, 0o500},
		{0o700, 0o700},
	} {
		dir := t.TempDir()
		bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
		if err := os.Chmod(dir, tc.before); err != nil {
			t.Fatal(err)
		}
		bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != tc.after {
			t.Errorf("directory %04o after Open is %04o, want %04o", tc.before, fi.Mode().Perm(), tc.after)
		}
		_ = os.Chmod(dir, 0o700)
	}
}

func TestOpen_doesNotOverwriteAGitignore(t *testing.T) {
	dir := t.TempDir()
	custom := []byte("# mine\n")
	if err := os.WriteFile(filepath.Join(dir, layout.FileGitignore), custom, 0600); err != nil {
		t.Fatal(err)
	}
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if got := bootstraptest.ReadFile(t, dir, layout.FileGitignore); string(got) != string(custom) {
		t.Errorf(".gitignore was rewritten: %q", got)
	}
}

// A read-only KeysDir (a mounted secret) cannot take a .gitignore. That is a
// warning, not a refusal.
func TestOpen_readOnlyDirectoryCannotWriteGitignoreButStillLoads(t *testing.T) {
	bootstraptest.NotRoot(t)
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Remove(filepath.Join(dir, layout.FileGitignore)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	log := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, log)
	if !log.Warned("could not write .gitignore") {
		t.Errorf("no .gitignore warning; warnings: %q", log.Warns)
	}
}

func TestOpen_adoptsAPreMetadataDirectoryWithoutTouchingTheKeys(t *testing.T) {
	dir := t.TempDir()
	_, pub, _ := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	before := map[string][]byte{}
	for _, name := range layout.KeyFileNames() {
		before[name] = bootstraptest.ReadFile(t, dir, name)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}

	log := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, log)

	for name, want := range before {
		if got := bootstraptest.ReadFile(t, dir, name); string(got) != string(want) {
			t.Errorf("%s changed while adopting the directory", name)
		}
	}
	meta, err := metadata.Read(dir)
	if err != nil || meta == nil || meta.KeyID != material.KeyID(pub) {
		t.Fatalf("metadata after adoption = %+v, %v", meta, err)
	}
	if log.Warned("generating a fresh key set") {
		t.Error("adopting an existing directory warned about generating keys")
	}
}

func TestOpen_rotatedKeyUpdatesTheRecordedKeyID(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	other := t.TempDir()
	_, otherPub, _ := bootstraptest.OpenOK(t, other, &bootstraptest.Recorder{})
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(dir, name), bootstraptest.ReadFile(t, other, name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	meta, err := metadata.Read(dir)
	if err != nil || meta.KeyID != material.KeyID(otherPub) {
		t.Fatalf("metadata after a rotation = %+v, %v; want key id %s", meta, err, material.KeyID(otherPub))
	}
}

// A read-only KeysDir is a supported deployment: the descriptor cannot be
// refreshed and the directory cannot be synced, and that is not a load failure.
func TestOpen_readOnlyDirectoryStillLoads(t *testing.T) {
	bootstraptest.NotRoot(t)
	dir := t.TempDir()
	_, pub, _ := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	log := &bootstraptest.Recorder{}
	_, got, _ := bootstraptest.OpenOK(t, dir, log)
	if !got.Equal(pub) {
		t.Fatal("a read-only directory loaded different keys")
	}
	if !log.Warned("could not write metadata.json") {
		t.Errorf("no warning about the descriptor; warnings: %q", log.Warns)
	}
}

func TestOpen_reportsLeftoverStagingDirectories(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Mkdir(filepath.Join(dir, layout.StagingPrefix+"deadbeefdeadbeef"), 0700); err != nil {
		t.Fatal(err)
	}
	log := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, log)
	if !log.Warned("can be deleted") {
		t.Errorf("no leftover warning: %q", log.Warns)
	}
}

func TestOpen_warnsWhenTheSecretsAreReadableByOthers(t *testing.T) {
	bootstraptest.PosixOnly(t)
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Chmod(filepath.Join(dir, layout.FilePrivateKey), 0o644); err != nil {
		t.Fatal(err)
	}
	log := &bootstraptest.Recorder{}
	bootstraptest.OpenOK(t, dir, log)
	if log.CountWarns("readable or writable by group or others") != 1 {
		t.Errorf("want exactly one mode warning; got %q", log.Warns)
	}
}
