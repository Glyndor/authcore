// Package secrets_test checks, for every module that keys itself from the
// provider's refresh secret, that it accepts a random one and that the modules
// that hold the secret keep their own copy of it.
package secrets_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
)

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

type keys struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (k keys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k keys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k keys) RefreshSecret() []byte          { return k.secret }
func (k keys) KeyID() string                  { return "test" }

type provider struct{ k keys }

func (provider) Config() authcore.Config { return authcore.DefaultConfig() }
func (provider) Logger() authcore.Logger { return silentLogger{} }
func (p provider) Keys() authcore.Keys   { return p.k }

func newProvider(t testing.TB, secret []byte) provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return provider{keys{priv: priv, pub: pub, secret: secret}}
}

func randomSecret(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type constructor struct {
	name string
	new  func(authcore.Provider) error
}

func constructors() []constructor {
	return []constructor{
		{"apikey", func(p authcore.Provider) error { _, err := apikey.New(p); return err }},
		{"credential", func(p authcore.Provider) error { _, err := credential.New(p); return err }},
		{"field", func(p authcore.Provider) error {
			_, err := field.New(p, field.Config{Context: "users.email"})
			return err
		}},
		{"jwt", func(p authcore.Provider) error { _, err := jwt.New[struct{}](p); return err }},
		{"totp", func(p authcore.Provider) error { _, err := totp.New(p); return err }},
	}
}

func TestHostile_Secrets_randomSecretIsAccepted(t *testing.T) {
	for _, c := range constructors() {
		t.Run(c.name, func(t *testing.T) {
			if err := c.new(newProvider(t, randomSecret(t))); err != nil {
				t.Fatalf("New: %v", err)
			}
		})
	}
}

// The module keeps its own copy: whoever supplied the buffer may clear it
// afterwards without changing what the module computes.
func TestHostile_Secrets_jwtKeepsItsOwnCopy(t *testing.T) {
	secret := randomSecret(t)
	m, err := jwt.New[struct{}](newProvider(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.HashRefreshToken("a-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	for i := range secret {
		secret[i] = 0
	}
	after, err := m.HashRefreshToken("a-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("clearing the provider's buffer changed the refresh token hash")
	}
}

func TestHostile_Secrets_totpKeepsItsOwnCopy(t *testing.T) {
	secret := randomSecret(t)
	m, err := totp.New(newProvider(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	const code = "ABCD-EFGH-JKLM"
	stored, err := m.HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	for i := range secret {
		secret[i] = 0
	}
	if i, ok := m.VerifyRecoveryCode(code, []string{stored}); !ok || i != 0 {
		t.Fatalf("a recovery hash made before the buffer was cleared no longer matches: %d %v", i, ok)
	}
}
