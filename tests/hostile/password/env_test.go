package password_test

// Fixtures for the hostile password tests. Everything goes through the public
// password API. The cost parameters are the lowest the module accepts so a
// test that hashes many times stays quick; the attacks below do not depend on
// the cost being high.

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

// strong satisfies the default policy: 12 characters with an upper case
// letter, a lower case letter, a digit and a symbol.
const strong = "Correct-Horse-9"

func lowCost() password.Config {
	return password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}
}

func newProvider(t testing.TB) authcore.Provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	prov, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatalf("authcore.New: %v", err)
	}
	return prov
}

func newModule(t testing.TB, cfg password.Config) *password.Password {
	t.Helper()
	m, err := password.New(newProvider(t), cfg)
	if err != nil {
		t.Fatalf("password.New: %v", err)
	}
	return m
}

// parts splits a PHC string into its six dollar-separated segments:
// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key.
func parts(t testing.TB, hash string) []string {
	t.Helper()
	p := strings.Split(hash, "$")
	if len(p) != 6 {
		t.Fatalf("hash has %d segments: %q", len(p), hash)
	}
	return p
}

func join(p ...string) string { return strings.Join(p, "$") }
