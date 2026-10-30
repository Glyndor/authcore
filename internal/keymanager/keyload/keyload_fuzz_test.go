package keyload

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// FuzzLoadRefreshSecret drives the refresh-secret file parser. It must never
// panic, must refuse any file over the read cap, and its verdict must match a
// standard hex decoding plus the material contract in both directions: an
// accepted file yields exactly the bytes its hex spelled, whatever the case or
// the whitespace around it.
func FuzzLoadRefreshSecret(f *testing.F) {
	good := hex.EncodeToString(fixedSecret())
	f.Add([]byte(good))
	f.Add([]byte(good + "\n"))
	f.Add([]byte("  " + good + " \r\n\t"))
	f.Add([]byte(strings.ToUpper(good)))
	f.Add([]byte(strings.Repeat("ab", layout.RefreshSecretLen)))
	f.Add([]byte(good[:62]))
	f.Add([]byte(good + good))
	f.Add([]byte("0x" + good))
	f.Add([]byte(good + "\x00"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("a"), layout.MaxKeyFileSize+1))

	path := filepath.Join(f.TempDir(), layout.FileRefreshSecret)
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		secret, err := loadRefreshSecret(path)
		if err != nil && secret != nil {
			t.Fatal("a secret was returned alongside an error")
		}
		want, ok := referenceSecret(data)
		if len(data) > layout.MaxKeyFileSize {
			ok = false
		}
		if (err == nil) != ok {
			t.Fatalf("accepted=%v, reference says %v for %q (err=%v)", err == nil, ok, data, err)
		}
		if err == nil && !bytes.Equal(secret, want) {
			t.Fatalf("the secret %x is not the hex the file held: %q", secret, data)
		}
	})
}

// fixedSecret is a random-looking 32-byte value derived from a fixed label.
func fixedSecret() []byte {
	sum := sha256.Sum256([]byte("authcore fuzz refresh secret"))
	return sum[:]
}

// FuzzLoadEd25519 drives the key-pair loader with two arbitrary files. Whatever
// it accepts must be a full-size pair whose public key is the one the private
// key derives, from files within the read cap.
func FuzzLoadEd25519(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{3, 5, 8, 13}, 64)))
	if err != nil {
		f.Fatal(err)
	}
	privPEM, _ := pemcodec.EncodePrivateKeyPEM(priv)
	pubPEM, _ := pemcodec.EncodePublicKeyPEM(pub)
	f.Add(privPEM, pubPEM)
	f.Add(pubPEM, privPEM)
	f.Add(privPEM, privPEM)
	otherPub, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{2, 7, 1, 8}, 64)))
	if err != nil {
		f.Fatal(err)
	}
	otherPubPEM, _ := pemcodec.EncodePublicKeyPEM(otherPub)
	f.Add(privPEM, otherPubPEM) // a valid pair's halves from two different sets
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte("A"), layout.MaxKeyFileSize+1), pubPEM)

	dir := f.TempDir()
	privPath, pubPath := filepath.Join(dir, layout.FilePrivateKey), filepath.Join(dir, layout.FilePublicKey)
	f.Fuzz(func(t *testing.T, privData, pubData []byte) {
		if err := os.WriteFile(privPath, privData, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pubPath, pubData, 0o600); err != nil {
			t.Fatal(err)
		}
		p, q, err := loadEd25519(privPath, pubPath)
		if err != nil {
			if p != nil || q != nil {
				t.Fatal("keys were returned alongside an error")
			}
			return
		}
		if len(privData) > layout.MaxKeyFileSize || len(pubData) > layout.MaxKeyFileSize {
			t.Fatal("accepted a file over the read cap")
		}
		if len(p) != ed25519.PrivateKeySize || len(q) != ed25519.PublicKeySize {
			t.Fatalf("accepted key sizes %d and %d", len(p), len(q))
		}
		if !p.Public().(ed25519.PublicKey).Equal(q) {
			t.Fatal("accepted a public key that is not the private key's")
		}
	})
}
