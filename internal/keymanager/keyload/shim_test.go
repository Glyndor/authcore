package keyload_test

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
)

// KeyManager is the test-side stand-in for the facade type: the three values
// the sub-packages hand back, with the same accessors the facade exposes. The
// tests in this package were written against keymanager.Load and
// keymanager.New and keep reading the same way; New (used to seed a directory)
// and Load below call the sub-packages the facade itself delegates to.
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
	priv, pub, secret, err := keyload.LoadOnly(dir, log)
	if err != nil {
		return nil, err
	}
	return &KeyManager{dir, priv, pub, secret}, nil
}

func (km *KeyManager) PrivateKey() ed25519.PrivateKey { return km.priv }
func (km *KeyManager) PublicKey() ed25519.PublicKey   { return km.pub }
func (km *KeyManager) RefreshSecret() []byte          { return km.secret }
func (km *KeyManager) KeyID() string                  { return material.KeyID(km.pub) }
func (km *KeyManager) Dir() string                    { return km.dir }
