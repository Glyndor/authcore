package jwt

// Guard test for the Ed25519 material check that New runs after the
// provider interface and Config checks. Measured on 2026-09-27 against
// v1.18.1, a caller-written Provider handing in a nil or 10-byte private
// key, a nil public key, or a public key from another pair had every token
// it issued fail VerifyAccessToken with "jwt: token is invalid"; a 10-byte
// private key also panicked in ed25519.Sign with "slice bounds out of
// range [32:0]". New now delegates to keymanager.ValidateMaterial, which
// refuses all five shapes at startup.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// keysFixtureProvider is a Provider that hands back exactly the keys the
// table case under test wants, alongside a valid 32-byte refresh secret.
// All fields are valid except the one named by the case name.
type keysFixtureProvider struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (p keysFixtureProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (p keysFixtureProvider) Logger() authcore.Logger { return silentLogger{} }
func (p keysFixtureProvider) Keys() authcore.Keys {
	return &fakeKeys{priv: p.priv, pub: p.pub, secret: p.secret}
}

// freshGuardKeys generates a fresh Ed25519 pair for one table case; the
// secret is always a valid 32-byte buffer so the only thing the case can
// fail on is the named Ed25519 material shape.
func freshGuardKeys(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate refresh secret: %v", err)
	}
	return pub, priv, secret
}

// TestNew_refusesUnusableKeyPair drives five unusable Ed25519 material
// shapes through New. Each case asserts both errors.Is(ErrInvalidConfig)
// and the message fragment the rule emits, paired with an acceptance case
// that constructs with a fresh pair, mints a token pair, and verifies the
// access token back through the same module.
//
// The table would otherwise crash the test binary on a panic; this test
// asserts no panic instead of relying on the runner's default panic
// recovery so a regression reports the case name rather than the runner's
// generic "panic: runtime error" line.
func TestNew_refusesUnusableKeyPair(t *testing.T) {
	type want struct {
		errIs    error
		fragment string
	}
	cases := map[string]struct {
		// build returns the provider for the case. Build rather than
		// store the keys inline so each case can construct a fresh
		// pair when it needs two.
		build func(t *testing.T) authcore.Provider
		want  want
	}{
		"nil private key": {
			build: func(t *testing.T) authcore.Provider {
				pub, _, secret := freshGuardKeys(t)
				return keysFixtureProvider{priv: nil, pub: pub, secret: secret}
			},
			want: want{
				errIs:    ErrInvalidConfig,
				fragment: "private key has wrong length: got 0",
			},
		},
		"10-byte private key": {
			build: func(t *testing.T) authcore.Provider {
				pub, _, secret := freshGuardKeys(t)
				return keysFixtureProvider{priv: ed25519.PrivateKey(make([]byte, 10)), pub: pub, secret: secret}
			},
			want: want{
				errIs:    ErrInvalidConfig,
				fragment: "private key has wrong length: got 10",
			},
		},
		"nil public key": {
			build: func(t *testing.T) authcore.Provider {
				_, priv, secret := freshGuardKeys(t)
				return keysFixtureProvider{priv: priv, pub: nil, secret: secret}
			},
			want: want{
				errIs:    ErrInvalidConfig,
				fragment: "public key has wrong length: got 0",
			},
		},
		"public key of another pair": {
			build: func(t *testing.T) authcore.Provider {
				_, priv, secret := freshGuardKeys(t)
				otherPub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate other pair: %v", err)
				}
				return keysFixtureProvider{priv: priv, pub: otherPub, secret: secret}
			},
			want: want{
				errIs:    ErrInvalidConfig,
				fragment: "public key does not match private key",
			},
		},
		"private key whose second half is another pair's public key": {
			build: func(t *testing.T) authcore.Provider {
				// A's seed + B's public half, returned with B's
				// public key as the provider's public key. The
				// length check, the priv.Public() comparison and
				// the pub vs priv comparison all pass: priv has
				// the correct Ed25519 size, priv.Public().(ed25519.
				// PublicKey) returns bytes 32..64 (B's public half),
				// which equals the provider's pub. Only the seed
				// round-trip catches the inconsistency.
				_, aPriv, secret := freshGuardKeys(t)
				_, bPriv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate B's pair: %v", err)
				}
				bPub := bPriv.Public().(ed25519.PublicKey)
				hybrid := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
				copy(hybrid[:ed25519.SeedSize], aPriv.Seed())
				copy(hybrid[ed25519.SeedSize:], bPub)
				return keysFixtureProvider{priv: hybrid, pub: bPub, secret: secret}
			},
			want: want{
				errIs:    ErrInvalidConfig,
				fragment: "private key is inconsistent",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("New panicked: %v", r)
				}
			}()

			p := tc.build(t)
			_, err := New[struct{}](p)
			if !errors.Is(err, tc.want.errIs) {
				t.Errorf("errors.Is(err, ErrInvalidConfig) = false; err = %v", err)
			}
			if !strings.Contains(err.Error(), tc.want.fragment) {
				t.Errorf("error does not name the failed rule %q: %v", tc.want.fragment, err)
			}
		})
	}

	// Acceptance twin: a valid pair constructs and the access token it
	// issues verifies back through the same module. Without this, the
	// guard could refuse everything (including a real pair) and the
	// table above would still pass.
	t.Run("valid pair accepts", func(t *testing.T) {
		pub, priv, secret := freshGuardKeys(t)
		p := keysFixtureProvider{priv: priv, pub: pub, secret: secret}
		j, err := New[struct{}](p)
		if err != nil {
			t.Fatalf("New with a valid pair: %v", err)
		}
		pair, err := j.CreateTokens(testSubject, struct{}{})
		if err != nil {
			t.Fatalf("CreateTokens with a valid pair: %v", err)
		}
		if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
			t.Errorf("VerifyAccessToken on the same module: %v", err)
		}
	})
}
