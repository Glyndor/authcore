// Package hostiletest holds the fixtures shared by the hostile password suites,
// one package per attack class under tests/hostile/password.
//
// Fixtures for the hostile password tests. Everything goes through the public
// password API. The cost parameters are the lowest the module accepts so a
// test that hashes many times stays quick; the attacks below do not depend on
// the cost being high.
package hostiletest

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

// Strong satisfies the default policy: 12 characters with an upper case
// letter, a lower case letter, a digit and a symbol.
const Strong = "Correct-Horse-9"

// LowCost returns the cheapest password config the module accepts.
func LowCost() password.Config {
	return password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}
}

// NewProvider builds a provider holding a fresh key pair.
func NewProvider(t testing.TB) authcore.Provider {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil) // a nil reader is crypto/rand, which does not fail
	secret := make([]byte, 32)
	_, _ = rand.Read(secret) // crypto/rand.Read never returns an error
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

// NewModule builds the password module over a fresh provider with cfg.
func NewModule(t testing.TB, cfg password.Config) *password.Password {
	t.Helper()
	m, err := password.New(NewProvider(t), cfg)
	if err != nil {
		t.Fatalf("password.New: %v", err)
	}
	return m
}

// Parts splits a PHC string into its six dollar-separated segments:
// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key.
func Parts(t testing.TB, hash string) []string {
	t.Helper()
	p := strings.Split(hash, "$")
	if len(p) != 6 {
		t.Fatalf("hash has %d segments: %q", len(p), hash)
	}
	return p
}

// Join joins the parts of a PHC string with the dollar separator.
func Join(p ...string) string { return strings.Join(p, "$") }
