package field

// Input-guard tests for field.New and for methods on a zero-value
// Field. Each rejection test asserts WHICH rejection (errors.Is with
// the sentinel, or a fragment of the message) so a test that fires on
// the wrong rule fails clearly. Each rejection has an acceptance twin
// just inside the limit.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// ---- test doubles ---------------------------------------------------------

// nilLoggerKeys is a Keys value whose accessor returns a nil Logger.
// A provider that surfaces a nil Logger is the second defect class
// New must reject.
type nilLoggerKeys struct{}

func (nilLoggerKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (nilLoggerKeys) PublicKey() ed25519.PublicKey   { return nil }
func (nilLoggerKeys) RefreshSecret() []byte          { return nil }
func (nilLoggerKeys) KeyID() string                  { return "" }

// nilKeysProvider is a Provider whose Keys() returns nil. The third
// defect class: New dereferences Keys() before validating, so a
// nil-valued Keys produces a nil dereference.
type nilKeysProvider struct{}

func (nilKeysProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilKeysProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilKeysProvider) Keys() authcore.Keys     { return nil }

// nilLoggerProvider is a Provider whose Logger() returns nil. A nil
// logger used to panic on the first log call one line later.
type nilLoggerProvider struct{}

func (nilLoggerProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilLoggerProvider) Logger() authcore.Logger { return nil }
func (nilLoggerProvider) Keys() authcore.Keys     { return sharedKeys{secret: make([]byte, 32)} }

// shortSecretProvider returns a 31-byte refresh secret.
type shortSecretProvider struct{}

func (shortSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (shortSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (shortSecretProvider) Keys() authcore.Keys     { return sharedKeys{secret: make([]byte, 31)} }

// nilSecretProvider returns a nil refresh secret.
type nilSecretProvider struct{}

func (nilSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilSecretProvider) Keys() authcore.Keys     { return sharedKeys{secret: nil} }

// goodSecretProvider hands back a 32-byte refresh secret.
type goodSecretProvider struct{ keys sharedKeys }

func (goodSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (goodSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (p goodSecretProvider) Keys() authcore.Keys   { return p.keys }

// ---- nil provider / logger / keys -----------------------------------------

// TestNew_rejectsNilProvider is the headline test for the second
// defect class: a nil Provider must be refused without panicking.
// If the constructor ever calls into p before the nil check, the
// test panics and the test runner reports it as a failure; that is
// the whole point. No recover here: a clean process must see an
// error, not a panic.
func TestNew_rejectsNilProvider(t *testing.T) {
	_, err := New(nil, Config{Context: "email"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilLogger covers a Provider whose Logger() returns
// nil. A nil logger used to panic on the first log call one line
// later.
func TestNew_rejectsNilLogger(t *testing.T) {
	_, err := New(nilLoggerProvider{}, Config{Context: "email"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilLogger) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilKeys covers a Provider whose Keys() returns nil.
// The dereference that used to follow this case no longer does.
func TestNew_rejectsNilKeys(t *testing.T) {
	_, err := New(nilKeysProvider{}, Config{Context: "email"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilKeys) = %v, want ErrInvalidConfig", err)
	}
}

// ---- refresh secret length ------------------------------------------------

// TestNew_rejectsNilRefreshSecret covers the first defect: a Provider
// whose Keys().RefreshSecret() returns nil. The constructor must
// refuse the module rather than build one whose AES and index keys
// are derived from an empty secret.
func TestNew_rejectsNilRefreshSecret(t *testing.T) {
	_, err := New(nilSecretProvider{}, Config{Context: "email"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil secret) = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "refresh secret has wrong length") {
		t.Errorf("error does not name the failed rule: %v", err)
	}
}

// TestNew_rejectsShortRefreshSecret covers a 31-byte secret.
func TestNew_rejectsShortRefreshSecret(t *testing.T) {
	_, err := New(shortSecretProvider{}, Config{Context: "email"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(31-byte secret) = %v, want ErrInvalidConfig", err)
	}
	if want := "got 31"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not name the length it saw: %v (want fragment %q)", err, want)
	}
}

// TestNew_acceptsThirtyTwoByteSecret is the acceptance twin.
func TestNew_acceptsThirtyTwoByteSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	p := goodSecretProvider{keys: sharedKeys{secret: secret}}
	if _, err := New(p, Config{Context: "email"}); err != nil {
		t.Errorf("New(32-byte secret) = %v, want nil", err)
	}
}

// ---- variadic Config guard ------------------------------------------------

// TestNew_rejectsMoreThanOneConfig pins the silent-drop behaviour:
// passing two Configs used to keep the first and drop the second.
func TestNew_rejectsMoreThanOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: sharedKeys{secret: secret}}
	_, err := New(p, Config{Context: "email"}, Config{Context: "phone"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with two Configs = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_acceptsOneConfig is the acceptance twin.
func TestNew_acceptsOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: sharedKeys{secret: secret}}
	if _, err := New(p, Config{Context: "phone"}); err != nil {
		t.Errorf("New with one Config = %v, want nil", err)
	}
}

// ---- zero-value methods ----------------------------------------------------

// TestZeroValue_BlindIndexFails pins the fourth defect on the Field
// module: a zero-value module used to return an index derived from an
// empty key and an empty context. BlindIndex now returns
// ErrNotInitialised and the new (string, error) signature lets it
// report that fact instead of silently producing a fingerprint.
func TestZeroValue_BlindIndexFails(t *testing.T) {
	var zero Field
	idx, err := zero.BlindIndex("alice@example.com")
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("BlindIndex on zero value = %v, want ErrNotInitialised", err)
	}
	if idx != "" {
		t.Errorf("BlindIndex on zero value returned %q, want empty string", idx)
	}
}

// TestZeroValue_DecryptFails pins the panic that used to happen when
// Decrypt ran on a zero-value module. The AEAD was nil and
// base64.RawStdEncoding.DecodeString had nothing to do; the package
// now refuses cleanly.
func TestZeroValue_DecryptFails(t *testing.T) {
	var zero Field
	plain, err := zero.Decrypt("anything")
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Decrypt on zero value = %v, want ErrNotInitialised", err)
	}
	if plain != "" {
		t.Errorf("Decrypt on zero value returned %q, want empty string", plain)
	}
}

// silence the unused import in case ed25519 is later removed
var _ = ed25519.PrivateKey(nil)

// TestZeroValue_EncryptFails pins down the rule that a Field which never went
// through New refuses to encrypt: the AEAD is nil, so the call would panic,
// and a module with no derived key has nothing to protect the plaintext with.
func TestZeroValue_EncryptFails(t *testing.T) {
	var f Field
	got, err := f.Encrypt("alice@example.com")
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Encrypt on zero value = %v, want ErrNotInitialised", err)
	}
	if got != "" {
		t.Errorf("Encrypt on zero value returned %q, want the empty string", got)
	}
}
