package keymanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Controls the 2026-09-25 review found working but unpinned, plus the two
// parsers it found lenient. Each test names the mutation that used to
// survive: without it, the control could be removed with the suite green.

// New only ever tightens KeysDir. os.Chmod(dir, dirMode) instead of
// mode&dirMode survived: a 0555 directory gained owner write.
func TestTightenDirMode_onlyEverTightens(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix mode bits and a non-root user")
	}
	for _, tc := range []struct{ before, after os.FileMode }{
		{0o555, 0o500}, // strips group and other, never adds owner write
		{0o750, 0o700},
		{0o500, 0o500},
	} {
		dir := t.TempDir()
		if _, err := New(dir, silentLog{}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		if err := os.Chmod(dir, tc.before); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dir, silentLog{}); err != nil {
			t.Fatalf("New on a %04o directory: %v", tc.before, err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != tc.after {
			t.Errorf("KeysDir %04o after New is %04o, want %04o", tc.before, fi.Mode().Perm(), tc.after)
		}
		_ = os.Chmod(dir, 0o700)
	}
}

// Recovery picks the staging directory whose private key matches the
// published one, whichever sorts first. With the comparison always true the
// first directory in name order was used, and an unrelated leftover that
// sorted first turned a recoverable state into a refusal.
func TestRecovery_picksTheStagingThatMatchesEvenWhenItSortsLast(t *testing.T) {
	dir := t.TempDir()
	unrelated, _, _, _, err := createStagingSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	matching, _, pub, _, err := createStagingSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, stagingPrefix+"0000000000000000")
	last := filepath.Join(dir, stagingPrefix+"ffffffffffffffff")
	if err := os.Rename(unrelated, first); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(matching, last); err != nil {
		t.Fatal(err)
	}
	// An interrupted publication: the private key is linked, the rest is not.
	if err := os.Link(filepath.Join(last, filePrivateKey), filepath.Join(dir, filePrivateKey)); err != nil {
		t.Fatal(err)
	}

	km, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("New on the interrupted publication: %v, want it recovered from the matching staging", err)
	}
	if want := computeKeyID(pub); km.KeyID() != want {
		t.Fatalf("recovered key id %q, want %q from the matching staging", km.KeyID(), want)
	}
	if !km.PublicKey().Equal(pub) {
		t.Fatal("the recovered public key is not the one whose private key was published")
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

	if _, err := FromPEM(privPEM, pubPEM, secret); err != nil {
		t.Fatalf("the canonical pair: %v, want accepted", err)
	}
	// Leading and trailing whitespace is what an editor or a secret manager
	// adds, not a second block.
	if _, err := FromPEM(append([]byte("\n"), privPEM...), append(pubPEM, '\n', '\n'), secret); err != nil {
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
			_, err := FromPEM(tc.privPEM, pubPEM, secret)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("FromPEM = %v, want a refusal naming %q", err, tc.reason)
			}
		})
	}
	if _, err := FromPEM(privPEM, privPEM, secret); err == nil || !strings.Contains(err.Error(), `labelled "PRIVATE KEY", want "PUBLIC KEY"`) {
		t.Fatalf("a private key in the public slot: %v, want the label refusal", err)
	}
}

// The error for a refresh secret that is not hex names the file and nothing
// of its contents; the hex package's own error quotes the offending byte.
func TestRefreshSecretErrorDoesNotEchoTheFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatal(err)
	}
	bad := "s3cr3t-value-that-is-not-hex-encoded-at-all-and-must-not-be-logged!\n"
	if err := os.WriteFile(filepath.Join(dir, fileRefreshSecret), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, silentLog{})
	if err == nil || !strings.Contains(err.Error(), "is not hex encoded") {
		t.Fatalf("Load = %v, want the not-hex refusal", err)
	}
	for _, fragment := range []string{"s3cr3t", "invalid byte", "U+", "'s'"} {
		if strings.Contains(err.Error(), fragment) {
			t.Errorf("the error echoes the file (%q): %v", fragment, err)
		}
	}
	// A well-formed file of the same length still loads, so the refusal is
	// about the encoding and not the length.
	good := hex.EncodeToString([]byte(strings.Repeat("k", 32))) + "\n"
	if err := os.WriteFile(filepath.Join(dir, fileRefreshSecret), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, silentLog{}); err != nil {
		t.Fatalf("Load with a hex secret: %v", err)
	}
}
