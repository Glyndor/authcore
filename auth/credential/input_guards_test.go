package credential

// Input-guard tests for credential.New. Each rejection test asserts
// WHICH rejection (errors.Is with the sentinel, or a fragment of the
// message) so a test that fires on the wrong rule fails clearly. Each
// rejection has an acceptance twin just inside the limit.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
)

// ---- test doubles ---------------------------------------------------------

// nilKeysProvider is a Provider whose Keys() returns nil. The third
// defect class: New dereferences Keys() before validating, so a
// nil-valued Keys produces a nil dereference.
type nilKeysProvider struct{}

func (nilKeysProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilKeysProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilKeysProvider) Keys() authcore.Keys     { return nil }

// nilLoggerProvider is a Provider whose Logger() returns nil.
type nilLoggerProvider struct{}

func (nilLoggerProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilLoggerProvider) Logger() authcore.Logger { return nil }
func (nilLoggerProvider) Keys() authcore.Keys     { return fakeKeys{secret: make([]byte, 32)} }

// shortSecretProvider returns a 31-byte refresh secret.
type shortSecretProvider struct{}

func (shortSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (shortSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (shortSecretProvider) Keys() authcore.Keys     { return fakeKeys{secret: make([]byte, 31)} }

// nilSecretProvider returns a nil refresh secret.
type nilSecretProvider struct{}

func (nilSecretProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (nilSecretProvider) Logger() authcore.Logger { return silentLogger{} }
func (nilSecretProvider) Keys() authcore.Keys     { return fakeKeys{secret: nil} }

// goodSecretProvider hands back a 32-byte refresh secret.
type goodSecretProvider struct{ keys fakeKeys }

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
	_, err := New(nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilLogger covers a Provider whose Logger() returns
// nil. A nil logger used to panic on the first log call one line
// later.
func TestNew_rejectsNilLogger(t *testing.T) {
	_, err := New(nilLoggerProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilLogger) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_rejectsNilKeys covers a Provider whose Keys() returns nil.
// The dereference that used to follow this case no longer does.
func TestNew_rejectsNilKeys(t *testing.T) {
	_, err := New(nilKeysProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nilKeys) = %v, want ErrInvalidConfig", err)
	}
}

// ---- refresh secret length ------------------------------------------------

// TestNew_rejectsNilRefreshSecret covers the first defect: a Provider
// whose Keys().RefreshSecret() returns nil. The constructor must
// refuse the module rather than build one whose HMAC pepper is empty.
func TestNew_rejectsNilRefreshSecret(t *testing.T) {
	_, err := New(nilSecretProvider{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(nil secret) = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "refresh secret has wrong length") {
		t.Errorf("error does not name the failed rule: %v", err)
	}
}

// TestNew_rejectsShortRefreshSecret covers a 31-byte secret.
func TestNew_rejectsShortRefreshSecret(t *testing.T) {
	_, err := New(shortSecretProvider{})
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
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	if _, err := New(p); err != nil {
		t.Errorf("New(32-byte secret) = %v, want nil", err)
	}
}

// ---- variadic Config guard ------------------------------------------------

// TestNew_rejectsMoreThanOneConfig pins the silent-drop behaviour.
func TestNew_rejectsMoreThanOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	_, err := New(p, Config{TTL: time.Hour}, Config{TTL: 2 * time.Hour})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New with two Configs = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_acceptsOneConfig is the acceptance twin.
func TestNew_acceptsOneConfig(t *testing.T) {
	secret := make([]byte, 32)
	p := goodSecretProvider{keys: fakeKeys{secret: secret}}
	if _, err := New(p, Config{TTL: time.Hour}); err != nil {
		t.Errorf("New with one Config = %v, want nil", err)
	}
}

// TestZeroValue_IssueFails and TestZeroValue_VerifyFails pin down the rule
// that a Credential which never went through New refuses to run: issuing
// would mint a token whose hash is computed under an empty HMAC pepper, and
// verifying would dereference a nil clock.
func TestZeroValue_IssueFails(t *testing.T) {
	var c Credential
	got, err := c.Issue("reset", "alice")
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Issue on zero value = %v, want ErrNotInitialised", err)
	}
	if got != nil {
		t.Errorf("Issue on zero value returned %+v, want nil", got)
	}
}

func TestZeroValue_VerifyFails(t *testing.T) {
	var c Credential
	err := c.Verify("reset", "alice", "token", "hash", time.Now())
	if !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Verify on zero value = %v, want ErrNotInitialised", err)
	}
}
