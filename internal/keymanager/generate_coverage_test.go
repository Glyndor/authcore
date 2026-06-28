package keymanager_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// seedValidKeyset generates a complete, valid set of key files in a fresh
// temp directory and returns the directory so a test can corrupt one file and
// re-run New() to exercise a specific load-failure path.
func seedValidKeyset(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keyset: New() error = %v", err)
	}
	return dir
}

// TestNew_corruptPublicKeyRejected covers the public-key load path: a valid
// private key alongside a public file with no PEM block must fail to load.
func TestNew_corruptPublicKeyRejected(t *testing.T) {
	dir := seedValidKeyset(t)

	pub := filepath.Join(dir, "ed25519_public.pem")
	if err := os.WriteFile(pub, []byte("not a pem block"), 0644); err != nil {
		t.Fatalf("corrupt public key: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected error for public key with no PEM block, got nil")
	}
}

// TestNew_mismatchedKeyPairRejected covers the sanity check that the loaded
// public key must match the private key: a public key from a different pair
// must be rejected.
func TestNew_mismatchedKeyPairRejected(t *testing.T) {
	dirA := seedValidKeyset(t)
	dirB := seedValidKeyset(t)

	foreignPub, err := os.ReadFile(filepath.Join(dirB, "ed25519_public.pem"))
	if err != nil {
		t.Fatalf("read foreign public key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirA, "ed25519_public.pem"), foreignPub, 0644); err != nil {
		t.Fatalf("swap public key: %v", err)
	}

	if _, err := keymanager.New(dirA, testLogger{t}); err == nil {
		t.Error("expected error for mismatched key pair, got nil")
	}
}

// TestNew_publicFileContainsPrivatePEMRejected covers the PKIX parse-error
// path in readPublicKey: a well-formed PEM block that is not a public key
// (here, a private-key PEM) must fail to parse as a public key.
func TestNew_publicFileContainsPrivatePEMRejected(t *testing.T) {
	dir := seedValidKeyset(t)

	privPEM, err := os.ReadFile(filepath.Join(dir, "ed25519_private.pem"))
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), privPEM, 0644); err != nil {
		t.Fatalf("swap private PEM into public file: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected error when public file holds a private-key PEM, got nil")
	}
}

// TestNew_privateFileContainsPublicPEMRejected covers the PKCS#8 parse-error
// path in readPrivateKey: a well-formed PEM block that is not a private key
// (here, a public-key PEM) must fail to parse as a private key.
func TestNew_privateFileContainsPublicPEMRejected(t *testing.T) {
	dir := seedValidKeyset(t)

	pubPEM, err := os.ReadFile(filepath.Join(dir, "ed25519_public.pem"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), pubPEM, 0600); err != nil {
		t.Fatalf("swap public PEM into private file: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected error when private file holds a public-key PEM, got nil")
	}
}

// TestNew_corruptRefreshSecretHexRejected covers the refresh-secret decode
// path: a file whose contents are not valid hex must fail to load.
func TestNew_corruptRefreshSecretHexRejected(t *testing.T) {
	dir := seedValidKeyset(t)

	secret := filepath.Join(dir, "refresh_secret.key")
	if err := os.WriteFile(secret, []byte("zzzz not hex\n"), 0600); err != nil {
		t.Fatalf("corrupt refresh secret: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected error for non-hex refresh secret, got nil")
	}
}

// TestNew_shortRefreshSecretRejected covers the refresh-secret length check:
// valid hex that decodes to fewer than the required bytes must be rejected.
func TestNew_shortRefreshSecretRejected(t *testing.T) {
	dir := seedValidKeyset(t)

	secret := filepath.Join(dir, "refresh_secret.key")
	if err := os.WriteFile(secret, []byte("abcd\n"), 0600); err != nil { // 2 bytes, want 32
		t.Fatalf("write short refresh secret: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected error for under-length refresh secret, got nil")
	}
}
