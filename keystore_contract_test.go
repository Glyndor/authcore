package authcore_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/internal/keymanager"
)

// customKeys is a consumer-side Keys implementation, the kind a secret-manager
// wrapper would write. Its methods tolerate a nil receiver on purpose: a test
// for the typed-nil check must fail by assertion when that check is missing,
// not by crashing the test binary.
type customKeys struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (k *customKeys) PrivateKey() ed25519.PrivateKey {
	if k == nil {
		return nil
	}
	return k.priv
}

func (k *customKeys) PublicKey() ed25519.PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

func (k *customKeys) RefreshSecret() []byte {
	if k == nil {
		return nil
	}
	return k.secret
}

func (k *customKeys) KeyID() string {
	if k == nil {
		return ""
	}
	return keymanager.KeyID(k.pub)
}

// mapKeys implements Keys on a map type, so that a nil map reaches New as a
// typed nil of a kind other than pointer.
type mapKeys map[string][]byte

func (m mapKeys) PrivateKey() ed25519.PrivateKey { return m["priv"] }
func (m mapKeys) PublicKey() ed25519.PublicKey   { return m["pub"] }
func (m mapKeys) RefreshSecret() []byte          { return m["secret"] }
func (m mapKeys) KeyID() string                  { return keymanager.KeyID(m["pub"]) }

// sliceKeys, funcKeys and chanKeys implement Keys on the remaining kinds whose
// zero value is nil. Nobody should write these, and New must still refuse
// their nil values instead of calling into them.
type sliceKeys [][]byte

func (s sliceKeys) at(i int) []byte {
	if i < len(s) {
		return s[i]
	}
	return nil
}
func (s sliceKeys) PrivateKey() ed25519.PrivateKey { return s.at(0) }
func (s sliceKeys) PublicKey() ed25519.PublicKey   { return s.at(1) }
func (s sliceKeys) RefreshSecret() []byte          { return s.at(2) }
func (s sliceKeys) KeyID() string                  { return keymanager.KeyID(s.at(1)) }

type funcKeys func() [][]byte

func (f funcKeys) material() sliceKeys {
	if f == nil {
		return nil
	}
	return f()
}
func (f funcKeys) PrivateKey() ed25519.PrivateKey { return f.material().PrivateKey() }
func (f funcKeys) PublicKey() ed25519.PublicKey   { return f.material().PublicKey() }
func (f funcKeys) RefreshSecret() []byte          { return f.material().RefreshSecret() }
func (f funcKeys) KeyID() string                  { return f.material().KeyID() }

type chanKeys chan struct{}

func (chanKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (chanKeys) PublicKey() ed25519.PublicKey   { return nil }
func (chanKeys) RefreshSecret() []byte          { return nil }
func (chanKeys) KeyID() string                  { return "" }

// valueKeys implements Keys on a struct value, which can never be a typed nil.
type valueKeys struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (v valueKeys) PrivateKey() ed25519.PrivateKey { return v.priv }
func (v valueKeys) PublicKey() ed25519.PublicKey   { return v.pub }
func (v valueKeys) RefreshSecret() []byte          { return v.secret }
func (v valueKeys) KeyID() string                  { return keymanager.KeyID(v.pub) }

// customStore returns exactly what it was given, like a store with no checks
// of its own.
type customStore struct {
	keys authcore.Keys
	err  error
}

func (s customStore) Load() (authcore.Keys, error) { return s.keys, s.err }

func newWithStore(ks authcore.KeyStore) (*authcore.AuthCore, error) {
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeyStore = ks
	return authcore.New(cfg)
}

// resize returns a copy of b cut or zero-padded to n bytes.
func resize(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func TestNew_customKeyStoreContract(t *testing.T) {
	priv, pub, secret := genMaterial(t)
	_, otherPub, _ := genMaterial(t)

	// The seed of one key followed by the public half of another: valid by
	// every length rule, and its second half equals the public key passed
	// with it, so only the derivation from the seed refuses it.
	spliced := append(append(ed25519.PrivateKey{}, priv.Seed()...), otherPub...)

	var nilPointer *customKeys
	var nilMap mapKeys
	var nilSlice sliceKeys
	var nilFunc funcKeys
	var nilChan chanKeys

	tests := []struct {
		name string
		keys authcore.Keys
		// want is a fragment of the error that only the intended check
		// produces. Empty means New must accept the store.
		want string
	}{
		{"valid pointer keys accepted", &customKeys{priv, pub, secret}, ""},
		{"valid struct value keys accepted", valueKeys{priv, pub, secret}, ""},
		{"struct value keys still validated", valueKeys{priv, pub, resize(secret, 31)}, "refresh secret has wrong length: got 31"},
		{"valid map keys accepted", mapKeys{"priv": priv, "pub": pub, "secret": secret}, ""},

		{"nil keys with nil error", nil, "returned nil Keys with a nil error"},
		{"typed nil pointer", nilPointer, "returned a nil *authcore_test.customKeys"},
		{"typed nil map", nilMap, "returned a nil authcore_test.mapKeys"},
		{"typed nil slice", nilSlice, "returned a nil authcore_test.sliceKeys"},
		{"typed nil func", nilFunc, "returned a nil authcore_test.funcKeys"},
		{"typed nil chan", nilChan, "returned a nil authcore_test.chanKeys"},
		{"valid slice keys accepted", sliceKeys{priv, pub, secret}, ""},
		{"valid func keys accepted", funcKeys(func() [][]byte { return [][]byte{priv, pub, secret} }), ""},

		{"private key one byte short", &customKeys{resize(priv, 63), pub, secret}, "private key has wrong length: got 63"},
		{"private key one byte long", &customKeys{resize(priv, 65), pub, secret}, "private key has wrong length: got 65"},
		{"private key is a bare seed", &customKeys{priv.Seed(), pub, secret}, "private key has wrong length: got 32"},
		{"public key one byte short", &customKeys{priv, resize(pub, 31), secret}, "public key has wrong length: got 31"},
		{"public key one byte long", &customKeys{priv, resize(pub, 33), secret}, "public key has wrong length: got 33"},
		{"private key spliced from two pairs", &customKeys{spliced, otherPub, secret}, "private key is inconsistent"},
		{"public key of another pair", &customKeys{priv, otherPub, secret}, "public key does not match private key"},
		{"refresh secret one byte short", &customKeys{priv, pub, resize(secret, 31)}, "refresh secret has wrong length: got 31"},
		{"refresh secret one byte long", &customKeys{priv, pub, resize(secret, 33)}, "refresh secret has wrong length: got 33"},
		{"refresh secret missing", &customKeys{priv, pub, nil}, "refresh secret has wrong length: got 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac, err := newWithStore(customStore{keys: tt.keys})

			if tt.want == "" {
				if err != nil {
					t.Fatalf("New refused a valid custom store: %v", err)
				}
				if !ac.Keys().PublicKey().Equal(pub) {
					t.Error("New did not keep the material the store returned")
				}
				return
			}

			if err == nil {
				t.Fatalf("New accepted the store; want an error containing %q", tt.want)
			}
			if ac != nil {
				t.Error("New returned a non-nil *AuthCore together with an error")
			}
			if !errors.Is(err, authcore.ErrKeyManager) {
				t.Errorf("error does not wrap ErrKeyManager: %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error names the wrong check\n got: %v\nwant fragment: %q", err, tt.want)
			}
		})
	}
}

// A store that reports its own failure keeps its own message: the contract
// check must not replace or hide it.
func TestNew_customKeyStoreErrorIsKept(t *testing.T) {
	errMiss := errors.New("secret authcore/signing not found")

	_, err := newWithStore(customStore{err: errMiss})
	if !errors.Is(err, authcore.ErrKeyManager) {
		t.Errorf("error does not wrap ErrKeyManager: %v", err)
	}
	if !errors.Is(err, errMiss) {
		t.Errorf("the store's own error was lost: %v", err)
	}
}

// The error a consumer sees must say what to return instead, and must name the
// KeyStore as the source of the bad material.
func TestNew_customKeyStoreErrorIsActionable(t *testing.T) {
	_, err := newWithStore(customStore{})
	if err == nil {
		t.Fatal("New accepted a store that returned (nil, nil)")
	}
	if want := "must return an error"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not tell the implementer what to do\n got: %v\nwant fragment: %q", err, want)
	}

	priv, pub, secret := genMaterial(t)
	_, err = newWithStore(customStore{keys: &customKeys{priv, pub, resize(secret, 31)}})
	if err == nil {
		t.Fatal("New accepted a 31-byte refresh secret")
	}
	if want := "KeyStore.Load returned unusable key material"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not name the KeyStore as the source\n got: %v\nwant fragment: %q", err, want)
	}
}

// End to end: material from a custom store signs a token that the jwt module
// then verifies, and the refresh hash round-trips.
func TestNew_customKeyStoreSignsAndVerifies(t *testing.T) {
	priv, pub, secret := genMaterial(t)

	ac, err := newWithStore(customStore{keys: &customKeys{priv, pub, secret}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	type claims struct {
		Role string `json:"role"`
	}
	mod, err := jwt.New[claims](ac, jwt.DefaultConfig())
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}

	const subject = "018f0c8e-9b2a-7c3a-8b1e-1234567890ab"
	pair, err := mod.CreateTokens(subject, claims{Role: "admin"})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}
	got, err := mod.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if got.Subject != subject {
		t.Errorf("subject = %q, want %q", got.Subject, subject)
	}
	if !mod.VerifyRefreshTokenHash(pair.RefreshToken, mod.HashRefreshToken(pair.RefreshToken)) {
		t.Error("refresh token hash did not round-trip")
	}
}
