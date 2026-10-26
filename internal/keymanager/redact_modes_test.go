package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

func newInMemory(t *testing.T) *keymanager.KeyManager {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	km, err := keymanager.FromKeys(priv, pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	return km
}

// String and GoString are two different renderings: the Go-syntax one carries
// the address-of marker, the plain one does not.
func TestKeyManager_PlainAndGoSyntaxRenderingsDiffer(t *testing.T) {
	km := newInMemory(t)

	plain, goSyntax := km.String(), km.GoString()
	if !strings.HasPrefix(plain, "keymanager.KeyManager{") {
		t.Errorf("String() = %q, want the plain form", plain)
	}
	if !strings.HasPrefix(goSyntax, "&keymanager.KeyManager{") {
		t.Errorf("GoString() = %q, want the address-of form", goSyntax)
	}
	if got := fmt.Sprintf("%v", km); got != plain {
		t.Errorf("%%v = %q, want String() = %q", got, plain)
	}
	if got := fmt.Sprintf("%#v", km); got != goSyntax {
		t.Errorf("%%#v = %q, want GoString() = %q", got, goSyntax)
	}
}

func TestKeyManager_NilReceiverRenderings(t *testing.T) {
	var km *keymanager.KeyManager
	if got := km.String(); got != "<nil>" {
		t.Errorf("String() on nil = %q", got)
	}
	if got := km.GoString(); got != "(*keymanager.KeyManager)(nil)" {
		t.Errorf("GoString() on nil = %q", got)
	}
}
