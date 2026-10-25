// Package bootstraptest is the test-side support for the bootstrap packages:
// a stand-in for the facade type plus the helpers the bootstrap, generate and
// load tests share. Only _test.go files import it.
package bootstraptest

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/keyload/loadonly"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
)

// KeyManager is the test-side stand-in for the facade type: the three values
// the sub-packages hand back, with the same accessors the facade exposes. The
// tests in this package were written against keymanager.New and keymanager.Load
// and keep reading the same way; New and Load below call the sub-packages the
// facade itself delegates to.
type KeyManager struct {
	dir    string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

// New is keymanager.New without the wrapper.
func New(dir string, log layout.Logger) (*KeyManager, error) {
	priv, pub, secret, err := bootstrap.Open(dir, log)
	if err != nil {
		return nil, err
	}
	return &KeyManager{dir, priv, pub, secret}, nil
}

// Load is keymanager.Load without the wrapper.
func Load(dir string, log layout.Logger) (*KeyManager, error) {
	priv, pub, secret, err := loadonly.Load(dir, log)
	if err != nil {
		return nil, err
	}
	return &KeyManager{dir, priv, pub, secret}, nil
}

// PrivateKey returns the signing key.
func (km *KeyManager) PrivateKey() ed25519.PrivateKey { return km.priv }

// PublicKey returns the verification key.
func (km *KeyManager) PublicKey() ed25519.PublicKey { return km.pub }

// RefreshSecret returns the refresh-token secret.
func (km *KeyManager) RefreshSecret() []byte { return km.secret }

// KeyID returns the identifier derived from the public key.
func (km *KeyManager) KeyID() string { return material.KeyID(km.pub) }

// Dir returns the key directory the set was opened from.
func (km *KeyManager) Dir() string { return km.dir }
