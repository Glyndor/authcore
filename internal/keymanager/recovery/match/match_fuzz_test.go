package match

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzFindStaging compares recovery with complete, distinct Ed25519 sets.
// Vary publication, missing files, mismatched pairs and invalid secrets; require
// the first complete set with a matching public key and published private bytes.
func FuzzFindStaging(f *testing.F) {
	sets := [2]map[string][]byte{stagingMaterial(f, "first"), stagingMaterial(f, "second")}
	for published := byte(0); published < 4; published++ {
		for state := byte(0); state < 8; state++ {
			f.Add("0123456789abcdef", published, state, byte(0))
			f.Add("0123456789abcdef", published, byte(0), state)
		}
	}
	f.Add("..", byte(2), byte(0), byte(0))
	f.Add("x\n[ERROR] forged", byte(1), byte(0), byte(0))
	f.Add("\xff\xfe", byte(0), byte(1), byte(2))
	f.Add(strings.Repeat("n", 200), byte(3), byte(0), byte(0))
	f.Add("", byte(0), byte(3), byte(3))
	f.Add("", byte(0), byte(4), byte(5))

	f.Fuzz(func(t *testing.T, suffix string, publication, stateA, stateB byte) {
		if !stagingSuffixAllowed(suffix) {
			t.Skip("not a portable directory entry name")
		}
		dir := t.TempDir()
		var published []byte
		switch publication % 4 {
		case 1, 2:
			published = sets[publication%4-1]["ed25519_private.pem"]
		case 3:
			// Same key as A, different bytes: recovery requires byte identity.
			published = append(bytes.Clone(sets[0]["ed25519_private.pem"]), '\n')
		}
		if published != nil {
			if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), published, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := ""
		for i, state := range []byte{stateA, stateB} {
			files := stagingVariant(sets[i], sets[1-i], state)
			staging := filepath.Join(dir, ".staging-"+string(rune('a'+i))+suffix)
			writeStagingMaterial(t, staging, files)
			if want == "" && referenceStagingComplete(files) &&
				(published == nil || bytes.Equal(published, files["ed25519_private.pem"])) {
				want = staging
			}
		}
		got, err := FindStaging(dir)
		if (err == nil) != (want != "") || got != want {
			t.Fatalf("FindStaging = %q, %v; want %q (publication=%d, states=%d/%d)", got, err, want, publication%4, stateA%8, stateB%8)
		}
		if want == "" && !errors.Is(err, ErrNoMatchingStaging) {
			t.Fatalf("unexpected refusal: %v", err)
		}
	})
}

func stagingSuffixAllowed(suffix string) bool {
	if strings.ContainsAny(suffix, "/\x00") || len(".staging-a"+suffix) > 255 {
		return false
	}
	return runtime.GOOS != "windows" || (utf8.ValidString(suffix) &&
		!strings.HasSuffix(suffix, ".") && !strings.HasSuffix(suffix, " ") &&
		!strings.ContainsAny(suffix, `<>:"|?*\`))
}

func stagingMaterial(t testing.TB, label string) map[string][]byte {
	t.Helper()
	seed := sha256.Sum256([]byte("staging private " + label))
	key := ed25519.NewKeyFromSeed(seed[:])
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256([]byte("staging refresh " + label))
	return map[string][]byte{
		"ed25519_private.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}),
		"ed25519_public.pem":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		"refresh_secret.key":  []byte(hex.EncodeToString(secret[:]) + "\n"),
	}
}

func stagingVariant(base, other map[string][]byte, state byte) map[string][]byte {
	files := make(map[string][]byte, len(base))
	for name, data := range base {
		files[name] = bytes.Clone(data)
	}
	switch state % 8 {
	case 1:
		delete(files, "ed25519_private.pem")
	case 2:
		delete(files, "ed25519_public.pem")
	case 3:
		delete(files, "refresh_secret.key")
	case 4:
		files["ed25519_public.pem"] = other["ed25519_public.pem"]
	case 5:
		files["refresh_secret.key"] = []byte("not hex")
	case 6:
		files["ed25519_private.pem"] = other["ed25519_private.pem"]
	case 7:
		files["ed25519_private.pem"] = append(files["ed25519_private.pem"], '\n')
	}
	return files
}

func writeStagingMaterial(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// referenceStagingComplete judges the controlled fixture domain, without any
// production loaders: three files, a standard-library key pair and one of the
// two nondegenerate SHA-256 refresh secrets used to construct the sets.
func referenceStagingComplete(files map[string][]byte) bool {
	privBlock, _ := pem.Decode(files["ed25519_private.pem"])
	pubBlock, _ := pem.Decode(files["ed25519_public.pem"])
	if len(files) != 3 || privBlock == nil || pubBlock == nil {
		return false
	}
	priv, privErr := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	pub, pubErr := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	key, privOK := priv.(ed25519.PrivateKey)
	public, pubOK := pub.(ed25519.PublicKey)
	if privErr != nil || pubErr != nil || !privOK || !pubOK || !key.Public().(ed25519.PublicKey).Equal(public) {
		return false
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(files["refresh_secret.key"])))
	first := sha256.Sum256([]byte("staging refresh first"))
	second := sha256.Sum256([]byte("staging refresh second"))
	return err == nil && (bytes.Equal(secret, first[:]) || bytes.Equal(secret, second[:]))
}
