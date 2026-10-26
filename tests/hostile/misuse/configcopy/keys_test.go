// Package configcopy mutates what the caller still holds after handing it to
// the library: Config values, the slices and pointers inside them, the key
// slices behind a KeyStore and the slices a Keys accessor returns. A module
// that kept a reference instead of a copy changes behaviour the moment the
// caller reuses its buffer, wipes a key for hygiene or edits a shared Config.
package configcopy

import (
	"bytes"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0xAA
	}
}

// A developer who wipes the buffers they passed to NewKeyStoreFromKeys, after
// New, must not change the keys the library already holds.
func TestMisuse_ConfigCopy_keyStoreInputsAreCopied(t *testing.T) {
	mat := hostiletest.NewMaterial(t)
	ref := mat.Clone()
	ks, err := authcore.NewKeyStoreFromKeys(mat.Priv, mat.Pub, mat.Secret)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	wipe(mat.Priv)
	wipe(mat.Pub)
	wipe(mat.Secret)

	k := ac.Keys()
	if !bytes.Equal(k.PrivateKey(), ref.Priv) {
		t.Error("wiping the caller's private key buffer changed the library's private key")
	}
	if !bytes.Equal(k.PublicKey(), ref.Pub) {
		t.Error("wiping the caller's public key buffer changed the library's public key")
	}
	if !bytes.Equal(k.RefreshSecret(), ref.Secret) {
		t.Error("wiping the caller's secret buffer changed the library's refresh secret")
	}
}

// The same wipe-after-use habit on the PEM buffers.
func TestMisuse_ConfigCopy_pemBuffersAreCopied(t *testing.T) {
	priv, pub, secret := hostiletest.NewPEM(t)
	ks, err := authcore.NewKeyStoreFromPEM(priv, pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(secret)
	wipe(priv)
	wipe(pub)
	wipe(secret)
	if !bytes.Equal(ac.Keys().RefreshSecret(), want) {
		t.Error("wiping the caller's secret buffer changed the library's refresh secret")
	}
	if got := len(ac.Keys().PrivateKey()); got != 64 {
		t.Errorf("private key length %d after wiping the PEM buffer", got)
	}
}
