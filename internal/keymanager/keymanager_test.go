package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// quietLog forwards what the key manager logs to the test log.
type quietLog struct{ t *testing.T }

func (l quietLog) Info(msg string, args ...any) { l.t.Logf("[INFO] "+msg, args...) }
func (l quietLog) Warn(msg string, args ...any) { l.t.Logf("[WARN] "+msg, args...) }

// KeyID is exported for the JWT module to index rotated keys by the same
// derivation. Its own package never called it, so it read as 0% while being
// exercised from next door — asserted here so the number stops lying.
func TestKeyID_matchesTheManagersOwnDerivation(t *testing.T) {
	dir := t.TempDir()
	km, err := keymanager.New(dir, quietLog{t})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if got := keymanager.KeyID(km.PublicKey()); got != km.KeyID() {
		t.Fatalf("KeyID(pub) = %q, want the manager's own %q", got, km.KeyID())
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if keymanager.KeyID(other) == km.KeyID() {
		t.Fatal("two different keys must not share an id")
	}
}

func pemPair(t *testing.T) (privPEM, pubPEM []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), priv
}

// The PEM decoders accept one block, of the expected type, with no headers
// and nothing else in the input. pem.Decode alone returned the first block
// wherever it sat and ignored the rest.
func TestPEMDecoders_acceptOneCanonicalBlockOnly(t *testing.T) {
	privPEM, pubPEM, _ := pemPair(t)
	otherPriv, _, _ := pemPair(t)
	secret := []byte(strings.Repeat("k", 32))

	if _, err := keymanager.FromPEM(privPEM, pubPEM, secret); err != nil {
		t.Fatalf("the canonical pair: %v, want accepted", err)
	}
	// Leading and trailing whitespace is what an editor or a secret manager
	// adds, not a second block.
	if _, err := keymanager.FromPEM(append([]byte("\n"), privPEM...), append(pubPEM, '\n', '\n'), secret); err != nil {
		t.Fatalf("whitespace around the blocks: %v, want accepted", err)
	}

	block, _ := pem.Decode(privPEM)
	relabelled := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes})
	for name, tc := range map[string]struct {
		privPEM []byte
		reason  string
	}{
		"two private blocks":      {append(append([]byte{}, privPEM...), otherPriv...), "more than one PEM block"},
		"text before the block":   {append([]byte("Bag Attributes\n    friendlyName: k\n"), privPEM...), "does not start with a PEM block"},
		"text after the block":    {append(append([]byte{}, privPEM...), []byte("trailing note\n")...), "more than one PEM block, or text after it"},
		"CERTIFICATE label":       {relabelled, `labelled "CERTIFICATE", want "PRIVATE KEY"`},
		"encryption headers":      {withHeaders, "carries headers"},
		"public key as private":   {pubPEM, `labelled "PUBLIC KEY", want "PRIVATE KEY"`},
		"BEGIN line and no block": {[]byte("-----BEGIN PRIVATE KEY-----\nnot a block\n"), "no PEM block found"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keymanager.FromPEM(tc.privPEM, pubPEM, secret)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("FromPEM = %v, want a refusal naming %q", err, tc.reason)
			}
		})
	}
	if _, err := keymanager.FromPEM(privPEM, privPEM, secret); err == nil || !strings.Contains(err.Error(), `labelled "PRIVATE KEY", want "PUBLIC KEY"`) {
		t.Fatalf("a private key in the public slot: %v, want the label refusal", err)
	}
}

// New and Load hand back a manager holding exactly what the directory holds,
// and Dir reports the path as passed in.
func TestNewAndLoad_wireTheAccessorsToTheSameKeys(t *testing.T) {
	dir := t.TempDir()
	created, err := keymanager.New(dir, quietLog{t})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	loaded, err := keymanager.Load(dir, quietLog{t})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if created.Dir() != dir || loaded.Dir() != dir {
		t.Errorf("Dir() = %q / %q, want %q", created.Dir(), loaded.Dir(), dir)
	}
	if !created.PrivateKey().Equal(loaded.PrivateKey()) || !created.PublicKey().Equal(loaded.PublicKey()) ||
		string(created.RefreshSecret()) != string(loaded.RefreshSecret()) || created.KeyID() != loaded.KeyID() {
		t.Fatal("New and Load disagree on the key set of one directory")
	}
	if err := keymanager.ValidateMaterial(created.PrivateKey(), created.PublicKey(), created.RefreshSecret()); err != nil {
		t.Fatalf("the generated material fails its own validation: %v", err)
	}
}

func TestNewAndLoad_failuresComeBackAsErrorsNotManagers(t *testing.T) {
	if km, err := keymanager.Load(t.TempDir()+"/absent", quietLog{t}); err == nil || km != nil {
		t.Errorf("Load of a missing directory = %v, %v", km, err)
	}
	file := t.TempDir() + "/file"
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if km, err := keymanager.New(file+"/keys", quietLog{t}); err == nil || km != nil {
		t.Errorf("New below a regular file = %v, %v", km, err)
	}
}

func TestDecodePEMBlock_delegatesToTheCodec(t *testing.T) {
	pemBytes, _, _ := pemPair(t)
	der, err := keymanager.DecodePEMBlock(pemBytes, "PRIVATE KEY", "test")
	if err != nil || len(der) == 0 {
		t.Fatalf("DecodePEMBlock = %d bytes, %v", len(der), err)
	}
	if _, err := keymanager.DecodePEMBlock(pemBytes, "PUBLIC KEY", "test"); err == nil {
		t.Fatal("a private key block was accepted as a public key")
	}
}
