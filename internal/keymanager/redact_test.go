package keymanager

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

// sentinelKeys builds key material whose bytes are recognisable, so a test can
// assert the material is absent from a rendering without ever printing a real
// key. The values are not valid Ed25519 material and are never used to sign.
func sentinelKeys() *KeyManager {
	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	secret := make([]byte, 32)
	for i := range priv {
		priv[i] = 0xA7
	}
	for i := range pub {
		pub[i] = 0xB3
	}
	for i := range secret {
		secret[i] = 0xC5
	}
	return &KeyManager{
		dir:           "/tmp/keys",
		privateKey:    priv,
		publicKey:     pub,
		refreshSecret: secret,
		keyID:         "sentinel",
	}
}

// TestFormattingRedactsEveryEncoding is the regression for the leak where
// %v and %+v printed the private key and the refresh secret as decimal byte
// slices while %#v printed them in hex.
//
// The encodings are the point of this test. A marker written for one of them
// walks straight past the same secret in the other, so both are asserted for
// every verb.
func TestFormattingRedactsEveryEncoding(t *testing.T) {
	km := sentinelKeys()

	// The same sentinel byte in the two encodings fmt uses for a byte slice.
	markers := map[string]string{
		"private key, decimal":    "167 167 167 167",
		"private key, hex":        "0xa7, 0xa7, 0xa7, 0xa7",
		"refresh secret, decimal": "197 197 197 197",
		"refresh secret, hex":     "0xc5, 0xc5, 0xc5, 0xc5",
		"public key, decimal":     "179 179 179 179",
		"public key, hex":         "0xb3, 0xb3, 0xb3, 0xb3",
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
		out := fmt.Sprintf(verb, km)
		for name, marker := range markers {
			if strings.Contains(out, marker) {
				t.Errorf("%s leaked the %s", verb, name)
			}
		}
	}
}

// TestFormattingRedactsThroughAWrapper covers the case that actually happens:
// nobody formats the key manager on purpose, they format a struct that holds
// it, or a slice of interfaces containing it.
func TestFormattingRedactsThroughAWrapper(t *testing.T) {
	km := sentinelKeys()
	wrapper := struct {
		Name string
		Keys *KeyManager
	}{Name: "startup", Keys: km}

	for _, verb := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(verb, wrapper)
		if strings.Contains(out, "167 167 167") || strings.Contains(out, "0xa7, 0xa7") {
			t.Errorf("%s of a wrapping struct leaked the private key", verb)
		}
	}
}

// TestFormattingStillIdentifiesTheManager guards the other direction: a
// redaction that prints nothing useful gets replaced by whoever next needs to
// debug a startup, and the leak comes back with it.
func TestFormattingStillIdentifiesTheManager(t *testing.T) {
	km := sentinelKeys()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, km)
		if !strings.Contains(out, "/tmp/keys") {
			t.Errorf("%s does not name the key directory: %s", verb, out)
		}
		if !strings.Contains(out, "sentinel") {
			t.Errorf("%s does not name the key id: %s", verb, out)
		}
		if !strings.Contains(out, redacted) {
			t.Errorf("%s does not say the secrets were redacted: %s", verb, out)
		}
	}
}

// TestFormattingANilManagerDoesNotPanic covers the diagnostic path taken when
// initialisation failed, which is exactly when someone reaches for a print.
func TestFormattingANilManagerDoesNotPanic(t *testing.T) {
	var km *KeyManager
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, km); out == "" {
			t.Errorf("%s of a nil manager rendered nothing", verb)
		}
	}
}
