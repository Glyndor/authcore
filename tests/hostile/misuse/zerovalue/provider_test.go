package zerovalue

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// constructor builds one module over a provider and reports only the error.
type constructor struct {
	name string
	sent error
	new  func(authcore.Provider) error
}

func constructors() []constructor {
	return []constructor{
		{"jwt", jwt.ErrInvalidConfig, func(p authcore.Provider) error { _, err := jwt.New[struct{}](p); return err }},
		{"password", password.ErrInvalidConfig, func(p authcore.Provider) error { _, err := password.New(p); return err }},
		{"totp", totp.ErrInvalidConfig, func(p authcore.Provider) error { _, err := totp.New(p); return err }},
		{"apikey", apikey.ErrInvalidConfig, func(p authcore.Provider) error { _, err := apikey.New(p); return err }},
		{"credential", credential.ErrInvalidConfig, func(p authcore.Provider) error { _, err := credential.New(p); return err }},
		{"field", field.ErrInvalidConfig, func(p authcore.Provider) error {
			_, err := field.New(p, field.Config{Context: "users.email"})
			return err
		}},
		{"email", email.ErrInvalidConfig, func(p authcore.Provider) error { _, err := email.New(p); return err }},
		{"username", username.ErrInvalidConfig, func(p authcore.Provider) error { _, err := username.New(p); return err }},
	}
}

// Providers that a hurried developer can produce. Each is wrong in one way,
// and every module needs the refresh secret and the logger from them.
func badProviders(t *testing.T) map[string]authcore.Provider {
	t.Helper()
	nilKeys, _ := hostiletest.NewProvider(t)
	nilKeys.K = nil
	noLogger, _ := hostiletest.NewProvider(t)
	noLogger.Log = nil
	shortSecret, _ := hostiletest.NewProvider(t)
	shortSecret.K.Secret = shortSecret.K.Secret[:16]
	noSecret, _ := hostiletest.NewProvider(t)
	noSecret.K.Secret = nil
	return map[string]authcore.Provider{
		"nil interface": nil,
		"zero AuthCore": &authcore.AuthCore{},
		"nil keys":      nilKeys,
		"nil logger":    noLogger,
		"short secret":  shortSecret,
		"nil secret":    noSecret,
	}
}

// Providers whose signing material is wrong. Only the JWT module signs, so
// only it has to refuse them; the other modules never read the pair.
func badSigningProviders(t *testing.T) map[string]authcore.Provider {
	t.Helper()
	nilPriv, _ := hostiletest.NewProvider(t)
	nilPriv.K.Priv = nil
	seedOnly, _ := hostiletest.NewProvider(t)
	seedOnly.K.Priv = seedOnly.K.Priv[:ed25519.SeedSize]
	foreignPub, _ := hostiletest.NewProvider(t)
	foreignPub.K.Pub = hostiletest.NewMaterial(t).Pub
	return map[string]authcore.Provider{
		"nil private key": nilPriv,
		"seed as private": seedOnly,
		"foreign public":  foreignPub,
	}
}

// keyFree names the modules that never read the key set, so a provider whose
// keys are wrong is still a working provider for them.
var keyFree = map[string]bool{"password": true, "email": true, "username": true}

// Every constructor refuses a provider that is not a working one, with its own
// ErrInvalidConfig and without a panic.
func TestMisuse_ZeroValue_constructorsRefuseBrokenProviders(t *testing.T) {
	for pname, p := range badProviders(t) {
		for _, c := range constructors() {
			if keyFree[c.name] && pname != "nil interface" && pname != "zero AuthCore" && pname != "nil logger" {
				continue
			}
			t.Run(c.name+"/"+pname, func(t *testing.T) {
				var err error
				hostiletest.NoPanic(t, c.name+".New", func() { err = c.new(p) })
				if err == nil {
					t.Fatal("a broken provider built a module")
				}
				if !errors.Is(err, c.sent) {
					t.Fatalf("error %v does not wrap %v", err, c.sent)
				}
			})
		}
	}
}

// The JWT module refuses signing material that would panic or fail later.
func TestMisuse_ZeroValue_jwtRefusesBrokenSigningMaterial(t *testing.T) {
	for pname, p := range badSigningProviders(t) {
		t.Run(pname, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "jwt.New", func() { _, err = jwt.New[struct{}](p) })
			if !errors.Is(err, jwt.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// The same constructors accept a hand-written provider that is correct, so the
// refusals above are about the provider and not about the test fixture.
func TestMisuse_ZeroValue_constructorsAcceptAWorkingCustomProvider(t *testing.T) {
	p, _ := hostiletest.NewProvider(t)
	for _, c := range constructors() {
		if err := c.new(p); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A KeyStore that breaks its contract fails New, not a later signature.
func TestMisuse_ZeroValue_brokenKeyStoreFailsNew(t *testing.T) {
	cases := map[string]authcore.KeyStore{
		"nil keys, nil error": storeFn(func() (authcore.Keys, error) { return nil, nil }),
		"typed nil keys":      storeFn(func() (authcore.Keys, error) { var k *hostiletest.Keys; return k, nil }),
		"empty material":      storeFn(func() (authcore.Keys, error) { return &hostiletest.Keys{}, nil }),
	}
	for name, ks := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "authcore.New", func() { _, err = authcore.New(authcore.Config{KeyStore: ks}) })
			if !errors.Is(err, authcore.ErrKeyManager) {
				t.Fatalf("got %v, want ErrKeyManager", err)
			}
		})
	}
}

type storeFn func() (authcore.Keys, error)

func (f storeFn) Load() (authcore.Keys, error) { return f() }
