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
	"github.com/Glyndor/authcore/auth/oauth"
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
		{"oauth", oauth.ErrInvalidConfig, func(p authcore.Provider) error {
			_, err := oauth.New(p, oauth.Config{ClientID: "client", RedirectURL: "https://app.example/callback", Provider: oauth.Google()})
			return err
		}},
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
	var nilProvider providerFn
	var nilProviderPtr *providerFn
	var nilKeysFn keysFn
	var nilKeysPtr *keysFn
	return map[string]authcore.Provider{
		"nil function provider": nilProvider,
		"nil pointer provider":  nilProviderPtr,
		"nil function keys":     providerKeys{Provider: nilKeys, keys: nilKeysFn},
		"nil pointer keys":      providerKeys{Provider: nilKeys, keys: nilKeysPtr},
		"nil interface":         nil,
		"zero AuthCore":         &authcore.AuthCore{},
		"nil keys":              nilKeys,
		"nil logger":            noLogger,
		"short secret":          shortSecret,
		"nil secret":            noSecret,
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
var keyFree = map[string]bool{"password": true, "email": true, "username": true, "oauth": true}

// Every constructor refuses a provider that is not a working one, with its own
// ErrInvalidConfig and without a panic.
func TestMisuse_ZeroValue_constructorsRefuseBrokenProviders(t *testing.T) {
	for pname, p := range badProviders(t) {
		for _, c := range constructors() {
			if keyFree[c.name] && pname != "nil interface" && pname != "zero AuthCore" && pname != "nil logger" &&
				pname != "nil function provider" && pname != "nil pointer provider" {
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
	pf := providerFn(func() authcore.Provider { return p })
	kf := keysFn(func() authcore.Keys { return p.Keys() })
	for name, provider := range map[string]authcore.Provider{
		"pointer": p, "function": pf, "function pointer": &pf,
		"keys function":         providerKeys{Provider: p, keys: kf},
		"keys function pointer": providerKeys{Provider: p, keys: &kf},
	} {
		for _, c := range constructors() {
			t.Run(c.name+"/"+name, func(t *testing.T) {
				if err := c.new(provider); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A KeyStore that breaks its contract fails New, not a later signature.
func TestMisuse_ZeroValue_brokenKeyStoreFailsNew(t *testing.T) {
	var nilStore storeFn
	var nilStorePtr *storeFn
	cases := map[string]struct {
		store authcore.KeyStore
		want  error
	}{
		"nil keys, nil error": {storeFn(func() (authcore.Keys, error) { return nil, nil }), authcore.ErrKeyManager},
		"typed nil keys":      {storeFn(func() (authcore.Keys, error) { var k *hostiletest.Keys; return k, nil }), authcore.ErrKeyManager},
		"nil function keys":   {storeFn(func() (authcore.Keys, error) { var k keysFn; return k, nil }), authcore.ErrKeyManager},
		"empty material":      {storeFn(func() (authcore.Keys, error) { return &hostiletest.Keys{}, nil }), authcore.ErrKeyManager},
		"nil function store":  {nilStore, authcore.ErrInvalidConfig},
		"nil pointer store":   {nilStorePtr, authcore.ErrInvalidConfig},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "authcore.New", func() { _, err = authcore.New(authcore.Config{KeyStore: tc.store}) })
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

type storeFn func() (authcore.Keys, error)

func (f storeFn) Load() (authcore.Keys, error) { return f() }

func TestMisuse_ZeroValue_acceptsWorkingCustomKeyStore(t *testing.T) {
	p, _ := hostiletest.NewProvider(t)
	store := storeFn(func() (authcore.Keys, error) { return p.Keys(), nil })
	for name, ks := range map[string]authcore.KeyStore{"function": store, "pointer": &store} {
		t.Run(name, func(t *testing.T) {
			ac, err := authcore.New(authcore.Config{KeyStore: ks})
			if err != nil {
				t.Fatal(err)
			}
			if ac.Keys() != p.Keys() {
				t.Error("New did not use the custom store's keys")
			}
		})
	}
}
