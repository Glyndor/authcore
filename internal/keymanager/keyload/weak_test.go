package keyload

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

func TestFiles_refusesAWeakRefreshSecret(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FileRefreshSecret, []byte(hex.EncodeToString(make([]byte, 32))+"\n"), 0600)

	_, _, _, err := Files(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "refresh secret") || !strings.Contains(err.Error(), "random") {
		t.Fatalf("Files = %v, want the weak-secret refusal", err)
	}
	if err := Check(dir); err == nil {
		t.Error("Check accepted a weak refresh secret")
	}
}

func TestFiles_refusesAWeakSigningSeed(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	privPEM, err := pemcodec.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pemcodec.EncodePublicKeyPEM(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keyloadtest.Put(t, dir, layout.FilePrivateKey, privPEM, 0600)
	keyloadtest.Put(t, dir, layout.FilePublicKey, pubPEM, 0644)

	_, _, _, err = Files(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "signing key seed") {
		t.Fatalf("Files = %v, want the weak-seed refusal", err)
	}
	if _, _, err := loadEd25519(filepath.Join(dir, layout.FilePrivateKey), filepath.Join(dir, layout.FilePublicKey)); err == nil {
		t.Error("loadEd25519 accepted a weak seed")
	}
}
