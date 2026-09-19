package field

// Config validation tests. They pin exactly one rejection
// case (empty Context) and the public New path wrapping it as
// ErrInvalidConfig. The shape mirrors auth/credential/config_test.go.

import (
	"errors"
	"testing"
)

// TestValidateConfig_RejectsEmpty pins the only rejection case: a
// Context of "" must fail validateConfig. Context has no default,
// because any default would put every field in one keyspace.
func TestValidateConfig_RejectsEmpty(t *testing.T) {
	if err := validateConfig(Config{Context: ""}); err == nil {
		t.Error("validateConfig(Context=\"\") = nil, want error")
	}
}

// TestValidateConfig_Accepts pins the only acceptance boundary:
// any non-empty Context is allowed. Context only names the
// field; the module does not constrain what the name is.
func TestValidateConfig_Accepts(t *testing.T) {
	for _, ctx := range []string{"email", "phone", "x", "a long column name with spaces"} {
		if err := validateConfig(Config{Context: ctx}); err != nil {
			t.Errorf("validateConfig(Context=%q) = %v, want nil", ctx, err)
		}
	}
}

// TestNew_RejectsInvalidConfig is the public New path. Every
// validateConfig failure must surface as ErrInvalidConfig so callers
// can distinguish startup errors from runtime errors.
func TestNew_RejectsInvalidConfig(t *testing.T) {
	_, err := New(newFakeProvider(t), Config{Context: ""})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(empty Context) = %v, want ErrInvalidConfig", err)
	}
}

// TestNew_AcceptsValidConfig: any value validateConfig accepts must
// be accepted by New too.
func TestNew_AcceptsValidConfig(t *testing.T) {
	for _, ctx := range []string{"email", "phone", "x"} {
		if _, err := New(newFakeProvider(t), Config{Context: ctx}); err != nil {
			t.Errorf("New(Context=%q) = %v, want nil", ctx, err)
		}
	}
}

// TestNew_DefaultConfigRejected pins the no-default rule: passing
// no Config at all routes through DefaultConfig, which returns the
// zero Config, which validateConfig rejects. A caller who forgets
// to set Context is told at startup, not silently given a shared
// keyspace.
func TestNew_DefaultConfigRejected(t *testing.T) {
	_, err := New(newFakeProvider(t))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("New(no Config) = %v, want ErrInvalidConfig", err)
	}
}

// TestApplyDefaults_IsPassThrough pins the "Context is not defaulted"
// rule of this package: applyDefaults does NOT fill an empty
// Context with a placeholder, because any placeholder would make
// every field share one keyspace. validateConfig is the only thing
// that decides what Context values are allowed.
func TestApplyDefaults_IsPassThrough(t *testing.T) {
	if got := applyDefaults(Config{}).Context; got != "" {
		t.Errorf("applyDefaults(Config{}).Context = %q, want empty (zero must reach validateConfig)", got)
	}
	if got := applyDefaults(Config{Context: "email"}).Context; got != "email" {
		t.Errorf("applyDefaults({email}).Context = %q, want email (explicit value must survive)", got)
	}
}
