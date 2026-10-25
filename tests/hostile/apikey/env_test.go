package apikey_test

// Fixtures for the hostile API key tests. Every test uses the public apikey
// API. A custom Provider lets a test hand the module a pepper the key store
// would never produce (empty, short, long), which is the empty-pepper attack.

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
)

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

type keys struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	secret []byte
}

func (k keys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k keys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k keys) RefreshSecret() []byte          { return k.secret }
func (k keys) KeyID() string                  { return "test" }

// provider is an authcore.Provider with a pepper of the test's choosing.
type provider struct{ k keys }

func (provider) Config() authcore.Config { return authcore.DefaultConfig() }
func (provider) Logger() authcore.Logger { return silentLogger{} }
func (p provider) Keys() authcore.Keys   { return p.k }

func newProviderWithPepper(t testing.TB, pepper []byte) provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return provider{keys{pub: pub, priv: priv, secret: pepper}}
}

func randomPepper(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("pepper: %v", err)
	}
	return b
}

func newModule(t testing.TB, cfg ...apikey.Config) *apikey.APIKey {
	t.Helper()
	m, err := apikey.New(newProviderWithPepper(t, randomPepper(t)), cfg...)
	if err != nil {
		t.Fatalf("apikey.New: %v", err)
	}
	return m
}
