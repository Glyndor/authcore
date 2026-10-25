package identity_test

// Fixtures for the hostile email and username tests.

import (
	"crypto/ed25519"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/username"
)

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

type keys struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func (k keys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k keys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k keys) RefreshSecret() []byte          { return make([]byte, 32) }
func (k keys) KeyID() string                  { return "test" }

type provider struct{ k keys }

func (provider) Config() authcore.Config { return authcore.DefaultConfig() }
func (provider) Logger() authcore.Logger { return silentLogger{} }
func (p provider) Keys() authcore.Keys   { return p.k }

func newProvider(t testing.TB) provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return provider{keys{pub: pub, priv: priv}}
}

func newEmail(t testing.TB, cfg ...email.Config) *email.Email {
	t.Helper()
	var (
		m   *email.Email
		err error
	)
	if len(cfg) > 0 {
		m, err = email.NewWithConfig(newProvider(t), cfg[0])
	} else {
		m, err = email.New(newProvider(t))
	}
	if err != nil {
		t.Fatalf("email.New: %v", err)
	}
	return m
}

func newUsername(t testing.TB, cfg ...username.Config) *username.Username {
	t.Helper()
	var (
		m   *username.Username
		err error
	)
	if len(cfg) > 0 {
		m, err = username.NewWithConfig(newProvider(t), cfg[0])
	} else {
		m, err = username.New(newProvider(t))
	}
	if err != nil {
		t.Fatalf("username.New: %v", err)
	}
	return m
}
