package jwt

// Input-guard tests for jwt.New and for methods on a zero-value
// JWT[T]. Each rejection test asserts WHICH rejection (errors.Is with
// the sentinel, or a fragment of the message) so a test that fires on
// the wrong rule fails clearly. Each rejection has an acceptance twin
// just inside the limit.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/auth/jwt/internal/refreshhash"
	"github.com/Glyndor/authcore/internal/keymanager"
)

// ---- test doubles ---------------------------------------------------------

// nilKeysProvider is a Provider whose Keys() returns nil.
type nilKeysProvider struct{}

func (nilKeysProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilKeysProvider) Logger() authcore.Logger { return jwttest.SilentLogger{} }
func (nilKeysProvider) Keys() authcore.Keys     { return nil }

// nilLoggerProvider is a Provider whose Logger() returns nil. The
// nil-logger check in New fires before the Ed25519-material check, so the
// fixture's private and public keys never reach it; they remain zero values
// to keep the test focused on the rule it names.
type nilLoggerProvider struct{}

func (nilLoggerProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilLoggerProvider) Logger() authcore.Logger { return nil }
func (nilLoggerProvider) Keys() authcore.Keys     { return &jwttest.Keys{Secret: make([]byte, 32)} }

// shortSecretProvider returns a 31-byte refresh secret alongside a
// generated Ed25519 pair, so New refuses the call on the secret-length rule
// and not on the new key-material rule.
type shortSecretProvider struct{}

func (shortSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (shortSecretProvider) Logger() authcore.Logger { return jwttest.SilentLogger{} }
func (shortSecretProvider) Keys() authcore.Keys {
	return &jwttest.Keys{Priv: guardTestPriv, Pub: guardTestPub, Secret: make([]byte, 31)}
}

// nilSecretProvider returns a nil refresh secret alongside a generated
// Ed25519 pair, so New refuses the call on the secret-length rule and not
// on the new key-material rule.
type nilSecretProvider struct{}

func (nilSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilSecretProvider) Logger() authcore.Logger { return jwttest.SilentLogger{} }
func (nilSecretProvider) Keys() authcore.Keys {
	return &jwttest.Keys{Priv: guardTestPriv, Pub: guardTestPub, Secret: nil}
}

// guardTestPriv / guardTestPub are a single Ed25519 pair shared by every
// guard-fixture provider. They are generated once at test binary start;
// the fixtures only need a valid pair to pass the new material check, not
// a distinct one per provider.
var (
	guardTestPub  ed25519.PublicKey
	guardTestPriv ed25519.PrivateKey
)

func init() {
	guardTestPub, guardTestPriv, _ = ed25519.GenerateKey(rand.Reader)
}

// goodSecretProvider hands back a 32-byte refresh secret with valid
// Ed25519 keys. New demands all three.
type goodSecretProvider struct{ keys *jwttest.Keys }

func (goodSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (goodSecretProvider) Logger() authcore.Logger { return jwttest.SilentLogger{} }
func (p goodSecretProvider) Keys() authcore.Keys   { return p.keys }

func newGoodSecretProvider(t testing.TB) goodSecretProvider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	_ = pub // keymanager.KeyID is unused here; the zero-value helper is enough
	_ = keymanager.KeyID(pub)
	return goodSecretProvider{keys: &jwttest.Keys{Priv: priv, Pub: pub, Secret: secret}}
}

// ---- nil provider / logger / keys -----------------------------------------

// TestNew_rejectsNilProvider is the headline test for the second
// defect class: a nil Provider must be refused without panicking.
// If the constructor ever calls into p before the nil check, the
// test panics and the test runner reports it as a failure; that is
// the whole point. No recover here: a clean process must see an
// error, not a panic.
func TestNew_rejectsNilProvider(t *testing.T) {
	_, err := New[struct{}](nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilLogger covers a Provider whose Logger() returns
// nil. A nil logger used to panic on the first log call one line
// later.
func TestNew_rejectsNilLogger(t *testing.T) {
	_, err := New[struct{}](nilLoggerProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilLogger) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilKeys covers a Provider whose Keys() returns nil.
// The dereference that used to follow this case no longer does.
func TestNew_rejectsNilKeys(t *testing.T) {
	_, err := New[struct{}](nilKeysProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilKeys) = %v, want ErrInvalidConfig", err)
	}
}

// ---- refresh secret length ------------------------------------------------

// TestNew_rejectsNilRefreshSecret covers the first defect: a Provider
// whose Keys().RefreshSecret() returns nil. The constructor must
// refuse the module rather than build one whose HMAC pepper is empty.
func TestNew_rejectsNilRefreshSecret(t *testing.T) {
	_, err := New[struct{}](nilSecretProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil secret) = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "refresh secret has wrong length") {
		t.Errorf("error does not name the failed rule: %v", err)
	}
}

// TestNew_rejectsShortRefreshSecret covers a 31-byte secret.
func TestNew_rejectsShortRefreshSecret(t *testing.T) {
	_, err := New[struct{}](shortSecretProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(31-byte secret) = %v, want ErrInvalidConfig", err)
	}
	if want := "got 31"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not name the length it saw: %v (want fragment %q)", err, want)
	}
}

// TestNew_acceptsThirtyTwoByteSecret is the acceptance twin.
func TestNew_acceptsThirtyTwoByteSecret(t *testing.T) {
	p := newGoodSecretProvider(t)
	if _, err := New[struct{}](p); err != nil {
		t.Errorf("New(32-byte secret) = %v, want nil", err)
	}
}

// ---- variadic Config guard ------------------------------------------------

// TestNew_rejectsMoreThanOneConfig pins the silent-drop behaviour:
// passing two Configs used to keep the first and drop the second, so
// a caller who relied on the second (e.g. a Denylist) could believe
// it was active when it was not. New must reject the call outright.
func TestNew_rejectsMoreThanOneConfig(t *testing.T) {
	p := newGoodSecretProvider(t)
	_, err := New[struct{}](p, DefaultConfig(), DefaultConfig())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with two Configs = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_acceptsOneConfig is the acceptance twin.
func TestNew_acceptsOneConfig(t *testing.T) {
	p := newGoodSecretProvider(t)
	if _, err := New[struct{}](p, DefaultConfig()); err != nil {
		t.Errorf("New with one Config = %v, want nil", err)
	}
}

// ---- zero-value methods ----------------------------------------------------

// TestZeroValue_RefreshHashFails pins the fourth defect on the JWT
// module: a zero-value module used to hash and compare refresh tokens
// under an empty HMAC secret. HashRefreshToken now returns
// ErrNotInitialised, which is the (string, error) signature that
// replaced the bare string.
func TestZeroValue_RefreshHashFails(t *testing.T) {
	var zero JWT[struct{}]
	hash, err := zero.HashRefreshToken("any-token")
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("HashRefreshToken on zero value = %v, want ErrNotInitialised", err)
	}
	if hash != "" {
		t.Errorf("HashRefreshToken on zero value returned %q, want empty string", hash)
	}
	// The stored hash is the one an empty key produces, which anyone can
	// compute; "any-hash" matched nothing with or without the guard.
	if zero.VerifyRefreshTokenHash("any-token", refreshhash.Compute("any-token", nil)) {
		t.Error("VerifyRefreshTokenHash on zero value accepted the empty-key hash")
	}
}

// Guard test for the Ed25519 material check that New runs after the
// provider interface and Config checks. Measured on 2026-09-27 against
// v1.18.1, a caller-written Provider handing in a nil or 10-byte private
// key, a nil public key, or a public key from another pair had every token
// it issued fail VerifyAccessToken with "jwt: token is invalid"; a 10-byte
// private key also panicked in ed25519.Sign with "slice bounds out of
// range [32:0]". New now delegates to keymanager.ValidateMaterial, which
// refuses all five shapes at startup.

// keysFixtureProvider is a Provider that hands back exactly the keys the
// table case under test wants, alongside a valid 32-byte refresh secret.
// All fields are valid except the one named by the case name.
type keysFixtureProvider struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (p keysFixtureProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (p keysFixtureProvider) Logger() authcore.Logger { return jwttest.SilentLogger{} }
func (p keysFixtureProvider) Keys() authcore.Keys {
	return &jwttest.Keys{Priv: p.priv, Pub: p.pub, Secret: p.secret}
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
		pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
		if err != nil {
			t.Fatalf("CreateTokens with a valid pair: %v", err)
		}
		if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
			t.Errorf("VerifyAccessToken on the same module: %v", err)
		}
	})
}

func TestNew_refusesAForgeablePreviousKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{make(ed25519.PublicKey, ed25519.PublicKeySize)}
	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "previous public key 0 cannot be trusted") {
		t.Fatalf("New with the all-zero previous key = %v, want ErrInvalidConfig naming the key", err)
	}

	cfg.PreviousPublicKeys = []ed25519.PublicKey{jwttest.NewProvider(t).Keys().PublicKey()}
	if _, err := New[struct{}](jwttest.NewProvider(t), cfg); err != nil {
		t.Fatalf("New with a real previous key = %v, want accepted", err)
	}
}

// A previous key with the current key's id would replace the current key in
// the verification set, and every token then issued failed its own
// verification (measured 2026-09-25 with a KeyStore reporting a stale kid).
// New refuses it; a different previous key is registered as before.
func TestNew_refusesAPreviousKeyWithTheCurrentKeyID(t *testing.T) {
	p := jwttest.NewProvider(t)
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{p.Keys().PublicKey()}
	_, err := New[struct{}](p, cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "has the current signing key's id") {
		t.Fatalf("New with the current key listed as previous = %v, want ErrInvalidConfig naming it", err)
	}

	cfg.PreviousPublicKeys = []ed25519.PublicKey{jwttest.NewProvider(t).Keys().PublicKey()}
	j, err := New[struct{}](p, cfg)
	if err != nil {
		t.Fatalf("New with a different previous key: %v", err)
	}
	if len(j.verifyKeys) != 2 {
		t.Fatalf("%d verification keys, want 2", len(j.verifyKeys))
	}
}

func TestRotation_badPreviousKeyRejectedAtNew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{[]byte("too-short")}
	if _, err := New[struct{}](jwttest.NewProvider(t), cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig for a wrong-length previous key, got %v", err)
	}
}
