package secret_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp"
)

type fakeKeys struct {
	secret []byte
}

func (fakeKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (fakeKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k fakeKeys) RefreshSecret() []byte        { return k.secret }
func (fakeKeys) KeyID() string                  { return "test" }

type fakeProvider struct{ keys authcore.Keys }

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p fakeProvider) Keys() authcore.Keys   { return p.keys }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newFakeProvider(tb testing.TB) fakeProvider {
	tb.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatalf("generate test HMAC secret: %v", err)
	}
	return fakeProvider{keys: fakeKeys{secret: secret}}
}

func newTOTP(tb testing.TB, cfg ...totp.Config) *totp.TOTP {
	tb.Helper()
	mod, err := totp.New(newFakeProvider(tb), cfg...)
	if err != nil {
		tb.Fatalf("totp.New: %v", err)
	}
	return mod
}
