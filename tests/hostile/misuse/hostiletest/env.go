// Package hostiletest holds the fixtures shared by the misuse-resistance
// suites under tests/hostile/misuse, one package per class of misuse. The
// adversary in these suites is a distracted developer, not an attacker with a
// forged token: a zero value, a copied Config mutated later, arguments in the
// wrong order, a struct handed to a logger. Every test goes through the public
// API, and the Env keeps the key material visible so a test can look for it in
// output that must not carry it.
package hostiletest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore"
)

// Subject and Other are two distinct UUID v7 subjects.
const (
	Subject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"
	Other   = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0002"
)

// Material is one set of key material, kept apart from the library so a test
// can search output for it.
type Material struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
}

// NewMaterial returns a fresh Ed25519 pair and a random 32-byte refresh secret.
func NewMaterial(t testing.TB) Material {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return Material{Priv: priv, Pub: pub, Secret: secret}
}

// Clone returns a deep copy, so a test can hand the library one copy and keep
// the other as the reference.
func (m Material) Clone() Material {
	return Material{
		Priv:   append(ed25519.PrivateKey(nil), m.Priv...),
		Pub:    append(ed25519.PublicKey(nil), m.Pub...),
		Secret: append([]byte(nil), m.Secret...),
	}
}

// RecordLogger is an authcore.Logger that remembers everything it was given,
// formatted the way a sink would, so a test can look for secrets in log output.
type RecordLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *RecordLogger) add(msg string, args []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(msg, args...))
}

// Debug records a line.
func (l *RecordLogger) Debug(msg string, args ...any) { l.add(msg, args) }

// Info records a line.
func (l *RecordLogger) Info(msg string, args ...any) { l.add(msg, args) }

// Warn records a line.
func (l *RecordLogger) Warn(msg string, args ...any) { l.add(msg, args) }

// Error records a line.
func (l *RecordLogger) Error(msg string, args ...any) { l.add(msg, args) }

// Text returns every recorded line, one per line.
func (l *RecordLogger) Text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// Env is one authcore instance with its key material kept visible.
type Env struct {
	Mat  Material
	AC   *authcore.AuthCore
	Log  *RecordLogger
	Conf authcore.Config
}

// NewEnv builds an AuthCore over in-memory keys. It touches no filesystem.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	mat := NewMaterial(t)
	ks, err := authcore.NewKeyStoreFromKeys(mat.Clone().Priv, mat.Clone().Pub, mat.Clone().Secret)
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	log := &RecordLogger{}
	cfg := authcore.Config{KeyStore: ks, Logger: log, EnableLogs: true}
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("authcore.New: %v", err)
	}
	return &Env{Mat: mat, AC: ac, Log: log, Conf: cfg}
}

// Keys is a caller-written authcore.Keys whose slices the test can mutate
// after handing it over.
type Keys struct {
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
	ID     string
}

// PrivateKey returns the private key slice as held, not a copy.
func (k *Keys) PrivateKey() ed25519.PrivateKey { return k.Priv }

// PublicKey returns the public key slice as held, not a copy.
func (k *Keys) PublicKey() ed25519.PublicKey { return k.Pub }

// RefreshSecret returns the secret slice as held, not a copy.
func (k *Keys) RefreshSecret() []byte { return k.Secret }

// KeyID returns the key id.
func (k *Keys) KeyID() string { return k.ID }

// Provider is a caller-written authcore.Provider over Keys.
type Provider struct {
	K   *Keys
	Cfg authcore.Config
	Log authcore.Logger
}

// Config returns the configuration.
func (p *Provider) Config() authcore.Config { return p.Cfg }

// Logger returns the logger.
func (p *Provider) Logger() authcore.Logger { return p.Log }

// Keys returns the key set.
// A nil K answers with a nil interface, the way a provider with no keys does,
// not with a typed nil that would panic inside the fixture.
func (p *Provider) Keys() authcore.Keys {
	if p.K == nil {
		return nil
	}
	return p.K
}

// NewProvider returns a hand-written Provider over a copy of mat.
func NewProvider(t testing.TB) (*Provider, Material) {
	t.Helper()
	mat := NewMaterial(t)
	c := mat.Clone()
	return &Provider{
		K:   &Keys{Priv: c.Priv, Pub: c.Pub, Secret: c.Secret, ID: "misuse-kid"},
		Cfg: authcore.DefaultConfig(),
		Log: &RecordLogger{},
	}, mat
}
