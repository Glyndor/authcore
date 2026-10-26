package binding_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/binding"
)

// The binding is stored in metadata.json, so its definition is on-disk format:
// HMAC-SHA256 keyed with the refresh secret over a fixed label and the public
// key. Changing the label or dropping it would orphan every existing
// directory and remove the domain separation from other uses of the secret.
func TestCompute_IsHMACOfTheLabelAndThePublicKey(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("authcore/keymanager/secret-binding/v1\x00"))
	mac.Write(pub)
	want := hex.EncodeToString(mac.Sum(nil))

	if got := binding.Compute(pub, secret); got != want {
		t.Fatalf("Compute = %s, want %s", got, want)
	}
	if !binding.Matches(want, pub, secret) {
		t.Error("Matches rejected the binding it should accept")
	}
	if binding.Matches(want, pub, []byte("another secret of the same length!")) {
		t.Error("Matches accepted a binding computed with another secret")
	}
}
