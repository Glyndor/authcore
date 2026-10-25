package totp_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp"
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

// The pepper keys the recovery code hashes. An empty, short or long one would
// make them a bare SHA-256 anyone can compute, so construction refuses it.
func TestHostile_Pepper_onlyA32ByteSecretIsAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for name, pepper := range map[string][]byte{
		"nil": nil, "empty": {}, "one byte": {1}, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33), "1 MiB": make([]byte, 1<<20),
	} {
		_, err := totp.New(provider{keys{pub: pub, priv: priv, secret: pepper}})
		if !errors.Is(err, totp.ErrInvalidConfig) {
			t.Errorf("%s: totp.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := totp.New(provider{keys{pub: pub, priv: priv, secret: make([]byte, 32)}}); err != nil {
		t.Errorf("control: a 32 byte pepper was refused: %v", err)
	}
}
