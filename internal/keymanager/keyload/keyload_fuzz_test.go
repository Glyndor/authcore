package keyload

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// FuzzLoadRefreshSecret drives the refresh-secret file parser. It must never
// panic, must refuse any file over the read cap, and must accept only a
// secret of exactly layout.RefreshSecretLen bytes that is the hex the file
// carried.
func FuzzLoadRefreshSecret(f *testing.F) {
	good := strings.Repeat("ab", layout.RefreshSecretLen)
	f.Add([]byte(good + "\n"))
	f.Add([]byte(strings.ToUpper(good)))
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
		if err != nil {
			if secret != nil {
				t.Fatal("a secret was returned alongside an error")
			}
			return
		}
		if len(data) > layout.MaxKeyFileSize {
			t.Fatalf("accepted a %d byte file, over the cap", len(data))
		}
		if len(secret) != layout.RefreshSecretLen {
			t.Fatalf("accepted a %d byte secret", len(secret))
		}
		if !strings.EqualFold(hex.EncodeToString(secret), strings.TrimSpace(string(data))) {
			t.Fatalf("the secret is not the hex the file held: %q", data)
		}
	})
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
