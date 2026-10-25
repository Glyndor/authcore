package keyload

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

type silentLog struct{}

func (silentLog) Info(string, ...any) {}
func (silentLog) Warn(string, ...any) {}

type recorder struct{ warnings []string }

func (r *recorder) Info(string, ...any) {}
func (r *recorder) Warn(msg string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(msg, args...))
}

type keySet struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

// writeSet drops a known-good trio into dir and returns the keys it holds.
func writeSet(t *testing.T, dir string) keySet {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := pemcodec.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pemcodec.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, layout.RefreshSecretLen)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	put(t, dir, layout.FilePrivateKey, privPEM, 0600)
	put(t, dir, layout.FilePublicKey, pubPEM, 0644)
	put(t, dir, layout.FileRefreshSecret, []byte(hex.EncodeToString(secret)+"\n"), 0600)
	return keySet{priv, pub, secret}
}

func put(t *testing.T, dir, name string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, perm); err != nil {
		t.Fatal(err)
	}
}

func TestFiles_returnsTheKeysOnDisk(t *testing.T) {
	dir := t.TempDir()
	want := writeSet(t, dir)

	priv, pub, secret, err := Files(dir, silentLog{})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if !priv.Equal(want.priv) || !pub.Equal(want.pub) || string(secret) != string(want.secret) {
		t.Fatal("Files returned keys other than the ones on disk")
	}
}

func TestFiles_errorsNameTheStepThatFailed(t *testing.T) {
	for name, tc := range map[string]struct {
		break_ func(t *testing.T, dir string)
		want   string
	}{
		"missing private key": {func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, layout.FilePrivateKey)) }, "ed25519 key pair: load private key"},
		"missing public key":  {func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, layout.FilePublicKey)) }, "ed25519 key pair: load public key"},
		"missing secret":      {func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, layout.FileRefreshSecret)) }, "refresh secret: read refresh secret"},
		"corrupt private key": {func(t *testing.T, dir string) { put(t, dir, layout.FilePrivateKey, []byte("junk"), 0600) }, "does not start with a PEM block"},
		"corrupt public key":  {func(t *testing.T, dir string) { put(t, dir, layout.FilePublicKey, []byte("junk"), 0644) }, "does not start with a PEM block"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeSet(t, dir)
			tc.break_(t, dir)
			_, _, _, err := Files(dir, silentLog{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Files = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestFiles_mismatchedPairIsRefusedWithRestoreAdvice(t *testing.T) {
	dir := t.TempDir()
	writeSet(t, dir)
	other := t.TempDir()
	writeSet(t, other)
	data, err := os.ReadFile(filepath.Join(other, layout.FilePublicKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	put(t, dir, layout.FilePublicKey, data, 0644)

	_, _, _, err = Files(dir, silentLog{})
	if err == nil || !strings.Contains(err.Error(), "restore the matching pair from a backup") {
		t.Fatalf("Files = %v, want the restore advice", err)
	}
	if strings.Contains(err.Error(), "delete both") {
		t.Errorf("the refusal advises deleting the pair: %v", err)
	}
}

func TestLoadRefreshSecret_refusals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, layout.FileRefreshSecret)

	put(t, dir, layout.FileRefreshSecret, []byte("s3cr3t-not-hex-at-all-but-quite-long!\n"), 0600)
	_, err := loadRefreshSecret(path)
	if err == nil || !strings.Contains(err.Error(), "is not hex encoded") {
		t.Fatalf("not hex: %v", err)
	}
	// The hex package's own error quotes the offending byte, a byte of the secret.
	for _, fragment := range []string{"s3cr3t", "invalid byte", "U+", "'s'"} {
		if strings.Contains(err.Error(), fragment) {
			t.Errorf("the error echoes the file (%q): %v", fragment, err)
		}
	}

	put(t, dir, layout.FileRefreshSecret, []byte(hex.EncodeToString(make([]byte, 31))+"\n"), 0600)
	if _, err := loadRefreshSecret(path); err == nil || !strings.Contains(err.Error(), "wrong length: got 31 bytes, want 32") {
		t.Fatalf("short secret: %v", err)
	}

	put(t, dir, layout.FileRefreshSecret, make([]byte, layout.MaxKeyFileSize+1), 0600)
	if _, err := loadRefreshSecret(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized secret: %v", err)
	}
}

func TestLoadRefreshSecret_acceptsSurroundingWhitespace(t *testing.T) {
	dir := t.TempDir()
	want := make([]byte, layout.RefreshSecretLen)
	_, _ = rand.Read(want)
	put(t, dir, layout.FileRefreshSecret, []byte("  "+hex.EncodeToString(want)+" \n\n"), 0600)
	got, err := loadRefreshSecret(filepath.Join(dir, layout.FileRefreshSecret))
	if err != nil || string(got) != string(want) {
		t.Fatalf("loadRefreshSecret = %x, %v", got, err)
	}
}

func TestFiles_warnsOnceForAReadableSecretButNotForThePublicKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := t.TempDir()
	writeSet(t, dir)
	if err := os.Chmod(filepath.Join(dir, layout.FileRefreshSecret), 0644); err != nil {
		t.Fatal(err)
	}
	log := &recorder{}
	if _, _, _, err := Files(dir, log); err != nil {
		t.Fatal(err)
	}
	if len(log.warnings) != 1 || !strings.Contains(log.warnings[0], layout.FileRefreshSecret) {
		t.Fatalf("warnings = %q, want exactly one, about the refresh secret", log.warnings)
	}
}
