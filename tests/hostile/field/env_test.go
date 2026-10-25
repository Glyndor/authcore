package field_test

// Fixtures for the hostile field tests. The tests keep the 32 byte secret so an
// independent AES-GCM and HMAC oracle can be built from it.

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/field"
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

// deployment is one pepper that several modules (one per column context) share,
// as an application's modules do.
type deployment struct {
	t      testing.TB
	pepper []byte
	prov   provider
}

func newDeployment(t testing.TB) *deployment {
	t.Helper()
	p := randomPepper(t)
	return &deployment{t: t, pepper: p, prov: newProviderWithPepper(t, p)}
}

func (d *deployment) column(context string) *field.Field {
	d.t.Helper()
	m, err := field.New(d.prov, field.Config{Context: context})
	if err != nil {
		d.t.Fatalf("field.New(%q): %v", context, err)
	}
	return m
}
