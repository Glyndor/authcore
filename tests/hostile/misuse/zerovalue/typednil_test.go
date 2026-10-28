package zerovalue

import (
	"crypto/ed25519"

	"github.com/Glyndor/authcore"
)

type providerFn func() authcore.Provider

func (f providerFn) Config() authcore.Config { return f().Config() }
func (f providerFn) Logger() authcore.Logger { return f().Logger() }
func (f providerFn) Keys() authcore.Keys     { return f().Keys() }

type keysFn func() authcore.Keys

func (f keysFn) PrivateKey() ed25519.PrivateKey { return f().PrivateKey() }
func (f keysFn) PublicKey() ed25519.PublicKey   { return f().PublicKey() }
func (f keysFn) RefreshSecret() []byte          { return f().RefreshSecret() }
func (f keysFn) KeyID() string                  { return f().KeyID() }

type providerKeys struct {
	authcore.Provider
	keys authcore.Keys
}

func (p providerKeys) Keys() authcore.Keys { return p.keys }
