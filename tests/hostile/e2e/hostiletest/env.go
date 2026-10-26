// Package hostiletest holds the fixtures shared by the end-to-end hostile
// tests under tests/hostile/e2e, one package per class. The tests there attack
// compositions of modules the way an application wires them: a real provider,
// several modules over one managed secret, and the tables the application is
// documented to keep, simulated in memory. The adversary sees every token and
// hash, controls the stores' timing through goroutines, and moves the clock by
// ageing the tokens it replays.
package hostiletest

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

// Subject and Other are two distinct UUID v7 user ids.
const (
	Subject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"
	Other   = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0002"
)

// Extra is the application payload carried under the "extra" claim.
type Extra struct {
	Role string `json:"role"`
}

// Env is one authcore deployment with its key material kept visible to the
// test: one managed secret shared by every module built from it.
type Env struct {
	Prov   authcore.Provider
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
}

// Check ends the test when err is not nil.
func Check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// NewEnv builds a deployment with fresh key material.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil) // a nil reader is crypto/rand, which does not fail
	secret := make([]byte, 32)
	_, _ = rand.Read(secret) // crypto/rand.Read never returns an error
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	Check(t, err)
	prov, err := authcore.New(authcore.Config{KeyStore: ks})
	Check(t, err)
	return &Env{Prov: prov, Priv: priv, Pub: pub, Secret: secret}
}

// JWT builds the jwt module of the deployment with cfg.
func (e *Env) JWT(t testing.TB, cfg jwt.Config) *jwt.JWT[Extra] {
	t.Helper()
	m, err := jwt.New[Extra](e.Prov, cfg)
	Check(t, err)
	return m
}

// Credential builds the credential module of the deployment with cfg.
func (e *Env) Credential(t testing.TB, cfg credential.Config) *credential.Credential {
	t.Helper()
	m, err := credential.New(e.Prov, cfg)
	Check(t, err)
	return m
}

// APIKey builds the apikey module of the deployment.
func (e *Env) APIKey(t testing.TB) *apikey.APIKey {
	t.Helper()
	m, err := apikey.New(e.Prov)
	Check(t, err)
	return m
}

// TOTP builds the totp module of the deployment with cfg.
func (e *Env) TOTP(t testing.TB, cfg totp.Config) *totp.TOTP {
	t.Helper()
	m, err := totp.New(e.Prov, cfg)
	Check(t, err)
	return m
}

// Field builds the field module of the deployment for one column context.
func (e *Env) Field(t testing.TB, context string) *field.Field {
	t.Helper()
	m, err := field.New(e.Prov, field.Config{Context: context})
	Check(t, err)
	return m
}
