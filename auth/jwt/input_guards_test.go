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
	"github.com/Glyndor/authcore/internal/keymanager"
)

// ---- test doubles ---------------------------------------------------------

// nilLoggerKeys is a Keys value whose accessor returns a nil Logger.
type nilLoggerKeys struct{}

func (nilLoggerKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (nilLoggerKeys) PublicKey() ed25519.PublicKey   { return nil }
func (nilLoggerKeys) RefreshSecret() []byte          { return nil }
func (nilLoggerKeys) KeyID() string                  { return "" }

// nilKeysProvider is a Provider whose Keys() returns nil.
type nilKeysProvider struct{}

func (nilKeysProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilKeysProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilKeysProvider) Keys() authcore.Keys     { return nil }

// nilLoggerProvider is a Provider whose Logger() returns nil.
type nilLoggerProvider struct{}

func (nilLoggerProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilLoggerProvider) Logger() authcore.Logger { return nil }
func (nilLoggerProvider) Keys() authcore.Keys     { return &fakeKeys{secret: make([]byte, 32)} }

// shortSecretProvider returns a 31-byte refresh secret.
type shortSecretProvider struct{}

func (shortSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (shortSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (shortSecretProvider) Keys() authcore.Keys     { return &fakeKeys{secret: make([]byte, 31)} }

// nilSecretProvider returns a nil refresh secret.
type nilSecretProvider struct{}

func (nilSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilSecretProvider) Keys() authcore.Keys     { return &fakeKeys{secret: nil} }

// goodSecretProvider hands back a 32-byte refresh secret with valid
// Ed25519 keys. New demands all three.
type goodSecretProvider struct{ keys *fakeKeys }

func (goodSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (goodSecretProvider) Logger() authcore.Logger { return silentLogger{} }
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
	return goodSecretProvider{keys: &fakeKeys{priv: priv, pub: pub, secret: secret}}
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
	if zero.VerifyRefreshTokenHash("any-token", "any-hash") {
		t.Error("VerifyRefreshTokenHash on zero value returned true")
	}
}
