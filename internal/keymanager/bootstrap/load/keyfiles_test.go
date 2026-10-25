package load_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// seedValidKeyset generates a complete, valid set of key files in a fresh
// temp directory and returns the directory so a test can corrupt one file and
// re-run New() to exercise a specific load-failure path.
func seedValidKeyset(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("seed keyset: bootstraptest.New() error = %v", err)
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

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
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

	if _, err := bootstraptest.New(dirA, bootstraptest.TestLogger{T: t}); err == nil {
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

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
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

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
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

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
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

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
		t.Error("expected error for under-length refresh secret, got nil")
	}
}

// writeValidEd25519Pair writes a real Ed25519 key pair into dir so the loader
// reaches the refresh-secret step.
func writeValidEd25519Pair(t *testing.T, dir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatalf("write private: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0600); err != nil {
		t.Fatalf("write public: %v", err)
	}
}

// TestNew_unreadableRefreshSecretRejected places a valid key pair beside a
// refresh_secret.key that is a directory. All three paths exist, so the
// consistency check passes and the loader proceeds — but reading the "file"
// fails, exercising readCapped's read-error path.
func TestNew_unreadableRefreshSecretRejected(t *testing.T) {
	dir := t.TempDir()
	writeValidEd25519Pair(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "refresh_secret.key"), 0700); err != nil {
		t.Fatalf("seed refresh-secret directory: %v", err)
	}

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
		t.Error("expected bootstraptest.New() to fail when refresh_secret.key is unreadable, got nil")
	}
}

// TestNew_nonEd25519KeyPairRejected seeds a syntactically valid PEM key pair
// that parses cleanly but is ECDSA, not Ed25519. This exercises the type
// assertions in readPrivateKey/readPublicKey — distinct from the existing
// corrupt-PEM and cross-PEM cases, where parsing itself fails.
func TestNew_nonEd25519KeyPairRejected(t *testing.T) {
	dir := t.TempDir()

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal ecdsa private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatalf("marshal ecdsa public: %v", err)
	}

	write := func(name, blockType string, der []byte) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
	write("ed25519_private.pem", "PRIVATE KEY", privDER)
	write("ed25519_public.pem", "PUBLIC KEY", pubDER)

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
		t.Error("expected bootstraptest.New() to reject a non-Ed25519 (ECDSA) key pair, got nil")
	}
}

// A descriptor that cannot be read at all is not the same as one that is
// absent: absent means the pre-marker layout and is adopted, while unreadable
// means the loader cannot tell what wrote the directory and must fail closed.
func TestNew_refusesAnUnreadableDescriptor(t *testing.T) {
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, layout.FileMetadata)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove descriptor: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("plant a directory at the descriptor path: %v", err)
	}

	if _, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t}); err == nil {
		t.Fatal("an unreadable descriptor must fail closed, not be treated as absent")
	}
}

func endlessStream(t *testing.T) string {
	t.Helper()
	const path = "/dev/zero"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available on %s: the read-time cap is not exercised here", path, runtime.GOOS)
	}
	return path
}

// End to end: a provisioned key set whose refresh secret has been replaced by
// a link to an endless stream. Load must refuse it, and New must refuse it
// too rather than read the slot as absent and generate a fresh set beside the
// existing private key. Measured when this was written: the refusal comes from
// the regular-file check, before any read.
func TestKeyFileLinkedToAnEndlessStreamIsRefused(t *testing.T) {
	stream := endlessStream(t)
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	privBefore, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, layout.FileRefreshSecret)
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stream, secret); err != nil {
		t.Fatal(err)
	}

	const notRegular = "not a regular file"
	if _, err := bootstraptest.Load(dir, bootstraptest.SilentLog{}); err == nil || !strings.Contains(err.Error(), notRegular) {
		t.Fatalf("Load = %v, want the refusal %q", err, notRegular)
	}
	if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err == nil || !strings.Contains(err.Error(), notRegular) {
		t.Fatalf("New = %v, want the refusal %q", err, notRegular)
	}
	privAfter, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey))
	if err != nil || !bytes.Equal(privBefore, privAfter) {
		t.Fatalf("the private key changed or went missing (%v)", err)
	}
}

// A KeysDir below a regular file cannot be inspected at all. New and Load
// report that, naming the directory, instead of treating it as absent.
func TestKeysDirBelowARegularFileIsReported(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(file, "keys")

	for name, open := range map[string]func(string, layout.Logger) (*bootstraptest.KeyManager, error){"New": bootstraptest.New, "Load": bootstraptest.Load} {
		_, err := open(dir, bootstraptest.SilentLog{})
		if err == nil || !strings.Contains(err.Error(), `inspect key directory "`+dir+`"`) {
			t.Errorf("%s(%q) = %v, want the inspect error naming the directory", name, dir, err)
		}
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 1 {
		t.Fatalf("something was created beside the file: %v, %v", entries, err)
	}
}

func TestNew_oversizedKeyFileRejected(t *testing.T) {
	// A valid Ed25519 PEM is ~200 bytes. An attacker-replaced key file
	// several megabytes long would otherwise be loaded whole into memory
	// before pem.Decode rejected it. The capped reader must surface a size
	// error before the allocation.
	dir := bootstraptest.SeedValidDir(t)
	oversized := make([]byte, 100*1024) // 100 KiB, well above the 4 KiB cap
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), oversized, 0600); err != nil {
		t.Fatalf("replace private key with an oversized file: %v", err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	assertSizeCapError(t, err)
}

func TestNew_oversizedPublicKeyFileRejected(t *testing.T) {
	// Regression guard for the public-key read path. Both key files must
	// be size-capped; if only the private side is checked an attacker who
	// can swap the public file still breaks startup.
	dir := bootstraptest.SeedValidDir(t)
	oversized := make([]byte, 100*1024)
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), oversized, 0644); err != nil {
		t.Fatalf("replace public key with an oversized file: %v", err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	assertSizeCapError(t, err)
}

func TestNew_oversizedRefreshSecretRejected(t *testing.T) {
	// The refresh secret loader shares the same capped reader. A ~100 KiB
	// secret file must be refused before it is hex-decoded.
	dir := bootstraptest.SeedValidDir(t)
	oversized := make([]byte, 100*1024)
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), oversized, 0600); err != nil {
		t.Fatalf("replace refresh secret with an oversized file: %v", err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.TestLogger{T: t})
	assertSizeCapError(t, err)
}

// assertSizeCapError fails unless err is the size-cap rejection. Asserting only
// that some error came back is what let these tests pass for three releases
// while never executing the cap they are named for.
func assertSizeCapError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error for a file over the size cap, got nil")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected the size-cap error, got a different failure: %v", err)
	}
}
