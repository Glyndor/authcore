package apikey_test

// Input-guard tests for apikey.New and for methods on a zero-value
// APIKey. Each rejection test asserts WHICH rejection (errors.Is with
// the sentinel, or a fragment of the message) so a test that fires on
// the wrong rule fails clearly. Each rejection has an acceptance twin
// just inside the limit.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
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
// logger panics on the first log call; New must catch it first.
type nilLoggerProvider struct{}

func (nilLoggerProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilLoggerProvider) Logger() authcore.Logger { return nil }
func (nilLoggerProvider) Keys() authcore.Keys     { return fakeKeys{secret: make([]byte, 32)} }

// shortSecretProvider returns a 31-byte refresh secret. The package
// demands 32 bytes; one byte short must be refused.
type shortSecretProvider struct{}

func (shortSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (shortSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (shortSecretProvider) Keys() authcore.Keys     { return fakeKeys{secret: make([]byte, 31)} }

// nilSecretProvider returns a nil refresh secret. The same rule
// applies: any length other than 32 bytes is refused.
type nilSecretProvider struct{}

func (nilSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilSecretProvider) Keys() authcore.Keys     { return fakeKeys{secret: nil} }

// goodSecretProvider hands back a 32-byte refresh secret. Used as the
// acceptance twin for every rejection above.
type goodSecretProvider struct{ keys authcore.Keys }

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
	_, err := apikey.New(nil)
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilLogger is the matching test for a Provider whose
// Logger() returns nil. A nil logger used to panic on the first log
// call one line later.
func TestNew_rejectsNilLogger(t *testing.T) {
	_, err := apikey.New(nilLoggerProvider{})
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New(nilLogger) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilKeys covers a Provider whose Keys() returns nil.
// The dereference that used to follow this case no longer does.
func TestNew_rejectsNilKeys(t *testing.T) {
	_, err := apikey.New(nilKeysProvider{})
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New(nilKeys) = %v, want ErrInvalidConfig", err)
	}
}

// ---- refresh secret length ------------------------------------------------

// TestNew_rejectsNilRefreshSecret covers the first defect: a Provider
// whose Keys().RefreshSecret() returns nil. The constructor must
// refuse the module rather than build one whose HMAC pepper is empty.
func TestNew_rejectsNilRefreshSecret(t *testing.T) {
	_, err := apikey.New(nilSecretProvider{})
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New(nil secret) = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "refresh secret has wrong length") {
		t.Errorf("error does not name the failed rule: %v", err)
	}
}

// TestNew_rejectsShortRefreshSecret covers a 31-byte secret: one byte
// short of the required length. The module would be buildable but
// insecure, so the constructor refuses.
func TestNew_rejectsShortRefreshSecret(t *testing.T) {
	_, err := apikey.New(shortSecretProvider{})
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New(31-byte secret) = %v, want ErrInvalidConfig", err)
	}
	if want := "got 31"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not name the length it saw: %v (want fragment %q)", err, want)
	}
}

// TestNew_acceptsThirtyTwoByteSecret is the acceptance twin for the
// two rejection cases above: a 32-byte secret constructs successfully.
// A regression that drops the length check would leave these tests
// passing but break the length check, so the pair pins both sides.
func TestNew_acceptsThirtyTwoByteSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	if _, err := apikey.New(p); err != nil {
		t.Errorf("New(32-byte secret) = %v, want nil", err)
	}
}

// ---- variadic Config guard ------------------------------------------------

// TestNew_rejectsMoreThanOneConfig pins the silent-drop behaviour:
// passing two Configs used to keep the first and drop the second, so
// a caller who relied on the second (e.g. a Denylist) could believe
// it was active when it was not. New must reject the call outright.
func TestNew_rejectsMoreThanOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	_, err := apikey.New(p, apikey.Config{Prefix: "ak"}, apikey.Config{Prefix: "svc"})
	if !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Errorf("New with two Configs = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_acceptsOneConfig is the acceptance twin: a single Config
// must still pass through cleanly. Without it, a regression that
// rejects every variadic Config (the opposite mistake) would not be
// caught here.
func TestNew_acceptsOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	if _, err := apikey.New(p, apikey.Config{Prefix: "svc"}); err != nil {
		t.Errorf("New with one Config = %v, want nil", err)
	}
}

// ---- zero-value methods ----------------------------------------------------

// TestZeroValue_GenerateFails pins the fourth defect on the APIKey
// module: a zero-value module used to mint keys under an empty HMAC
// pepper. Generate now refuses with ErrNotInitialised.
func TestZeroValue_GenerateFails(t *testing.T) {
	var zero apikey.APIKey
	_, err := zero.Generate()
	if !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("Generate on zero value = %v, want ErrNotInitialised", err)
	}
}

// TestZeroValue_VerifyReturnsFalse pins the second half of the same
// defect: a zero-value module used to verify any presented key
// against the empty-pepper hash of itself. Verify now returns false.
func TestZeroValue_VerifyReturnsFalse(t *testing.T) {
	var zero apikey.APIKey
	key := "ak_" + strings.Repeat("0", 32) + "_anything"

	// The hash anybody can compute for this key when the module has no
	// pepper. A zero value that still hashed would compare its own output
	// against this value and report a match, which is the whole failure:
	// "no key was used" must never read as "the key matched".
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte(key))
	unkeyed := hex.EncodeToString(mac.Sum(nil))

	if zero.Verify(key, unkeyed) {
		t.Error("Verify on zero value accepted a hash computed under an empty pepper")
	}
	if zero.Verify(key, "stored") {
		t.Error("Verify on zero value returned true for an unrelated hash")
	}
}

// silence the unused import in case ed25519 is later removed
var _ = ed25519.PrivateKey(nil)
