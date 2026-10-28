// Package jwttest holds the fixtures the jwt packages' tests share: in-memory
// key material, a Provider built on it, a silent logger and a Rig that wires
// the issue, verify and rotation packages together under a clock the test
// moves. It is test support: only _test.go files import it.
package jwttest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/keymanager"
)

// Epoch is the fixed reference time used in all time-sensitive tests.
var Epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// Subject is a valid UUID v7 used across most tests.
const Subject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"

// Keys satisfies authcore.Keys using in-memory key material.
type Keys struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
}

// PrivateKey returns the Ed25519 signing key.
func (k *Keys) PrivateKey() ed25519.PrivateKey { return k.Priv }

// PublicKey returns the Ed25519 verification key.
func (k *Keys) PublicKey() ed25519.PublicKey { return k.Pub }

// RefreshSecret returns the HMAC secret for refresh-token hashes.
func (k *Keys) RefreshSecret() []byte { return k.Secret }

// KeyID returns the "kid" derived from the public key.
func (k *Keys) KeyID() string { return keymanager.KeyID(k.Pub) }

// NewKeys generates fresh key material.
func NewKeys(t testing.TB) *Keys {
	t.Helper()
	// Go 1.26: rand parameter to GenerateKey is always ignored — nil is explicit.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate test Ed25519 keys: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate test HMAC secret: %v", err)
	}
	return &Keys{Priv: priv, Pub: pub, Secret: secret}
}

// Provider satisfies authcore.Provider using in-memory state.
type Provider struct{ K *Keys }

// NewProvider returns a Provider backed by freshly generated keys.
func NewProvider(t testing.TB) *Provider { return &Provider{K: NewKeys(t)} }

// Config returns the default authcore configuration.
func (p *Provider) Config() authcore.Config { return authcore.DefaultConfig() }

// Logger returns a logger that discards everything.
func (p *Provider) Logger() authcore.Logger { return SilentLogger{} }

// Keys returns the provider's key material.
func (p *Provider) Keys() authcore.Keys { return p.K }

// SilentLogger satisfies authcore.Logger and discards all output.
type SilentLogger struct{}

// Debug discards the message.
func (SilentLogger) Debug(string, ...any) {}

// Info discards the message.
func (SilentLogger) Info(string, ...any) {}

// Warn discards the message.
func (SilentLogger) Warn(string, ...any) {}

// Error discards the message.
func (SilentLogger) Error(string, ...any) {}

// Header decodes the JOSE header of a compact JWT string.
func Header(t testing.TB, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}
