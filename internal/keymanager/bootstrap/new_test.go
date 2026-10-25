package bootstrap_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
)

// newKM is a helper that creates a KeyManager in t.TempDir() and fails fast
// on any error.
func newKM(t *testing.T) *bootstraptest.KeyManager {
	t.Helper()
	km, err := bootstraptest.New(t.TempDir(), bootstraptest.TestLogger{T: t})
	if err != nil {
		t.Fatalf("bootstraptest.New() unexpected error: %v", err)
	}
	return km
}

// ----- generation -------------------------------------------------------------

func TestNew_generatesAllFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	if err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}

	wantFiles := []string{
		".gitignore",
		"ed25519_private.pem",
		"ed25519_public.pem",
		"refresh_secret.key",
	}
	for _, f := range wantFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
			t.Errorf("expected file %q was not created", f)
		}
	}
}

func TestNew_partialKeyDirIsRejected(t *testing.T) {
	// Removing any single managed file while the others remain must fail closed,
	// rather than silently regenerating it. A regenerated refresh secret would
	// invalidate every stored refresh-token hash.
	for _, remove := range []string{
		"refresh_secret.key",
		"ed25519_private.pem",
		"ed25519_public.pem",
	} {
		t.Run("missing_"+remove, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
				t.Fatalf("initial bootstraptest.New() error = %v", err)
			}
			if err := os.Remove(filepath.Join(dir, remove)); err != nil {
				t.Fatalf("remove %q: %v", remove, err)
			}
			if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
				t.Errorf("expected an error for a key dir missing %q, got nil", remove)
			}
		})
	}
}

func TestNew_keyMaterialHasCorrectSize(t *testing.T) {
	km := newKM(t)

	if got := len(km.PrivateKey()); got != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey() length = %d, want %d", got, ed25519.PrivateKeySize)
	}
	if got := len(km.PublicKey()); got != ed25519.PublicKeySize {
		t.Errorf("PublicKey() length = %d, want %d", got, ed25519.PublicKeySize)
	}
	if got := len(km.RefreshSecret()); got != 32 {
		t.Errorf("RefreshSecret() length = %d, want 32", got)
	}
}

func TestNew_publicKeyMatchesPrivateKey(t *testing.T) {
	km := newKM(t)

	derived := km.PrivateKey().Public().(ed25519.PublicKey)
	if !derived.Equal(km.PublicKey()) {
		t.Error("public key does not match the public half of the private key")
	}
}

func TestNew_keysAreDifferentAcrossInstances(t *testing.T) {
	km1 := newKM(t)
	km2 := newKM(t)

	if km1.PrivateKey().Equal(km2.PrivateKey()) {
		t.Error("two independently generated private keys must not be equal")
	}
}

// ----- persistence ------------------------------------------------------------

func TestNew_loadsExistingKeysOnSecondRun(t *testing.T) {
	dir := t.TempDir()
	log := bootstraptest.TestLogger{T: t}

	km1, err := bootstraptest.New(dir, log)
	if err != nil {
		t.Fatalf("first bootstraptest.New() error = %v", err)
	}

	km2, err := bootstraptest.New(dir, log)
	if err != nil {
		t.Fatalf("second bootstraptest.New() error = %v", err)
	}

	if !km1.PrivateKey().Equal(km2.PrivateKey()) {
		t.Error("private key changed between runs")
	}
	if !km1.PublicKey().Equal(km2.PublicKey()) {
		t.Error("public key changed between runs")
	}
	if string(km1.RefreshSecret()) != string(km2.RefreshSecret()) {
		t.Error("refresh secret changed between runs")
	}
}

// ----- .gitignore -------------------------------------------------------------

func TestNew_gitignoreCreated(t *testing.T) {
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}

	path := filepath.Join(dir, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(".gitignore not created: %v", err)
	}
	// The .gitignore must contain a catch-all pattern that prevents
	// every file in the directory from being committed. A comment-only
	// file leaves the keys exposed to git add; this test asserts the
	// catch-all, not just the file's existence.
	if len(data) == 0 {
		t.Error(".gitignore is empty")
	}
	if !strings.Contains(string(data), "*") {
		t.Errorf(".gitignore has no catch-all pattern, content=%q", data)
	}
}

func TestNew_gitignoreNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	custom := []byte("# custom\n*.bak\n")
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), custom, 0600); err != nil {
		t.Fatalf("write custom .gitignore: %v", err)
	}

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if string(data) != string(custom) {
		t.Error("existing .gitignore was overwritten")
	}
}

// ----- file permissions -------------------------------------------------------

func TestNew_privateKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission model does not apply on Windows")
	}

	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "ed25519_private.pem"))
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("private key permissions = %04o, want 0600", got)
	}
}

func TestNew_refreshSecretPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission model does not apply on Windows")
	}

	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "refresh_secret.key"))
	if err != nil {
		t.Fatalf("stat refresh secret: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("refresh secret permissions = %04o, want 0600", got)
	}
}

// ----- error paths ------------------------------------------------------------

func TestNew_inconsistentStateReturnsError(t *testing.T) {
	dir := t.TempDir()

	// Create only the private key — the public key is missing.
	// New() must detect the inconsistency and return an error.
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("initial bootstraptest.New() error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ed25519_public.pem")); err != nil {
		t.Fatalf("remove public key: %v", err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	if err == nil {
		t.Error("expected error for inconsistent key state, got nil")
	}
}

func TestNew_dirReturnsCorrectPath(t *testing.T) {
	dir := t.TempDir()
	km, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	if err != nil {
		t.Fatalf("bootstraptest.New() error = %v", err)
	}
	if km.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", km.Dir(), dir)
	}
}

// ----- KeyID -----------------------------------------------------------------

func TestKeyID_isNonEmpty(t *testing.T) {
	km := newKM(t)
	if km.KeyID() == "" {
		t.Error("KeyID() returned empty string")
	}
}

func TestKeyID_is16HexCharacters(t *testing.T) {
	km := newKM(t)
	id := km.KeyID()
	if len(id) != 16 {
		t.Fatalf("KeyID() length = %d, want 16", len(id))
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("KeyID() contains non-hex character %q", c)
		}
	}
}

func TestKeyID_isDeterministicAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	log := bootstraptest.TestLogger{T: t}

	km1, err := bootstraptest.New(dir, log)
	if err != nil {
		t.Fatalf("first bootstraptest.New() error = %v", err)
	}
	km2, err := bootstraptest.New(dir, log)
	if err != nil {
		t.Fatalf("second bootstraptest.New() error = %v", err)
	}

	if km1.KeyID() != km2.KeyID() {
		t.Errorf("KeyID changed between loads: %q vs %q", km1.KeyID(), km2.KeyID())
	}
}

func TestKeyID_differentKeysProduceDifferentIDs(t *testing.T) {
	km1 := newKM(t)
	km2 := newKM(t)

	if km1.KeyID() == km2.KeyID() {
		t.Error("independently generated keys must not produce the same KeyID")
	}
}

// readCapped refuses an oversized key file twice: once on the size Stat
// reports, and again when the read itself delivers more than the cap. The
// second check is for a file that grows between the Stat and the read. Until
// these tests nothing reached it, so it could be deleted with the suite green.
// /dev/zero stands in for such a file: Stat reports zero bytes and the read
// never ends. Through Load and New a device never gets that far, because the
// regular-file check refuses it first; the end-to-end test below pins that.
