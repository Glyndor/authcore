package load_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

var otherSecret = []byte("9f2c7a41d83be5106ac9347fe20b6d58c14a97e3b05d28f6710ec4a93b8d5f26\n")

// A secret that is not the recorded one is refused, and nothing is rewritten.
func TestOpen_refusesASecretThatIsNotTheRecordedOne(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	meta := filepath.Join(dir, layout.FileMetadata)
	before, _ := os.ReadFile(meta)
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), otherSecret, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "does not belong to its key pair") {
		t.Fatalf("Open = %v, want the binding refusal", err)
	}
	if after, _ := os.ReadFile(meta); string(after) != string(before) {
		t.Error("the descriptor was rewritten by a refused start")
	}
}

// Dropping the binding line is the documented way to adopt another secret.
func TestOpen_adoptsAnotherSecretOnceTheBindingIsRemoved(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), otherSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}

	log := &bootstraptest.Recorder{}
	if _, _, secret := bootstraptest.OpenOK(t, dir, log); hex.EncodeToString(secret)+"\n" != string(otherSecret) {
		t.Fatal("the adopted secret is not the one on disk")
	}
	if _, _, _, err := bootstrap.Open(dir, log); err != nil {
		t.Fatalf("the rebound directory no longer loads: %v", err)
	}
}

// A staging directory holding the published private key but different other
// files is a standing refusal, however many times the start is repeated.
func TestOpen_refusesAStagingDirectoryThatContradictsThePublishedFiles(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	recoverytest.StagingFrom(t, dir, "contradiction", dir)
	if err := os.WriteFile(filepath.Join(dir, layout.FileRefreshSecret), otherSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if _, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{}); err == nil ||
			!strings.Contains(err.Error(), "two different initialisations") {
			t.Fatalf("start %d: Open = %v, want the two-initialisations refusal", i, err)
		}
	}
}
