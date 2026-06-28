package keymanager_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// testLogger satisfies the unexported keymanager.logger interface via
// structural typing and forwards entries to the test log.
type testLogger struct{ t *testing.T }

func (l testLogger) Info(msg string, args ...any) { l.t.Logf("[INFO] "+msg, args...) }
func (l testLogger) Warn(msg string, args ...any) { l.t.Logf("[WARN] "+msg, args...) }

// newKM is a helper that creates a KeyManager in t.TempDir() and fails fast
// on any error.
func newKM(t *testing.T) *keymanager.KeyManager {
	t.Helper()
	km, err := keymanager.New(t.TempDir(), testLogger{t})
	if err != nil {
		t.Fatalf("keymanager.New() unexpected error: %v", err)
	}
	return km
}

// ----- generation -------------------------------------------------------------

func TestNew_oversizedKeyFileRejected(t *testing.T) {
	// A valid Ed25519 PEM is ~200 bytes. An attacker-replaced key file
	// several megabytes long would previously be loaded whole into
	// memory before pem.Decode rejected it. The capped reader must
	// surface a size error before the allocation.
	dir := t.TempDir()
	oversized := make([]byte, 100*1024) // 100 KiB, well above the 4 KiB cap
	// Pair both key files so New() takes the "load existing" branch.
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), oversized, 0600); err != nil {
		t.Fatalf("seed oversized private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), []byte("fake"), 0644); err != nil {
		t.Fatalf("seed public key: %v", err)
	}

	_, err := keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected error when private key file exceeds size cap, got nil")
	}
}

func TestNew_oversizedPublicKeyFileRejected(t *testing.T) {
	// Regression guard for the public-key read path. Both key files must
	// be size-capped; if only the private side is checked an attacker who
	// can swap the public file still breaks startup.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), []byte("fake-but-small"), 0600); err != nil {
		t.Fatalf("seed private key: %v", err)
	}
	oversized := make([]byte, 100*1024)
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), oversized, 0644); err != nil {
		t.Fatalf("seed oversized public key: %v", err)
	}

	_, err := keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected error when public key file exceeds size cap, got nil")
	}
}

func TestNew_oversizedRefreshSecretRejected(t *testing.T) {
	// The refresh secret loader shares the same capped reader. A ~100 KiB
	// secret file must be refused before it is hex-decoded.
	dir := t.TempDir()
	// Let the key-pair step succeed by letting New() generate fresh keys.
	oversized := make([]byte, 100*1024)
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), oversized, 0600); err != nil {
		t.Fatalf("seed oversized refresh secret: %v", err)
	}

	_, err := keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected error when refresh secret file exceeds size cap, got nil")
	}
}

func TestNew_generatesAllFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("New() error = %v", err)
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
			if _, err := keymanager.New(dir, testLogger{t}); err != nil {
				t.Fatalf("initial New() error = %v", err)
			}
			if err := os.Remove(filepath.Join(dir, remove)); err != nil {
				t.Fatalf("remove %q: %v", remove, err)
			}
			if _, err := keymanager.New(dir, testLogger{t}); err == nil {
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
	log := testLogger{t}

	km1, err := keymanager.New(dir, log)
	if err != nil {
		t.Fatalf("first New() error = %v", err)
	}

	km2, err := keymanager.New(dir, log)
	if err != nil {
		t.Fatalf("second New() error = %v", err)
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
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("New() error = %v", err)
	}

	path := filepath.Join(dir, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(".gitignore not created: %v", err)
	}
	// The .gitignore must contain a catch-all pattern.
	if len(data) == 0 {
		t.Error(".gitignore is empty")
	}
}

func TestNew_gitignoreNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	custom := []byte("# custom\n*.bak\n")
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), custom, 0600); err != nil {
		t.Fatalf("write custom .gitignore: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("New() error = %v", err)
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
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("New() error = %v", err)
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
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("New() error = %v", err)
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
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("initial New() error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ed25519_public.pem")); err != nil {
		t.Fatalf("remove public key: %v", err)
	}

	_, err := keymanager.New(dir, testLogger{t})
	if err == nil {
		t.Error("expected error for inconsistent key state, got nil")
	}
}

func TestNew_dirReturnsCorrectPath(t *testing.T) {
	dir := t.TempDir()
	km, err := keymanager.New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("New() error = %v", err)
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
	log := testLogger{t}

	km1, err := keymanager.New(dir, log)
	if err != nil {
		t.Fatalf("first New() error = %v", err)
	}
	km2, err := keymanager.New(dir, log)
	if err != nil {
		t.Fatalf("second New() error = %v", err)
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
