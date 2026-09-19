package credential

// Config validation tests. They pin three specific rejection
// cases (zero TTL, negative TTL, 25 hours) plus a positive boundary
// (24 hours must be accepted).

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestValidateConfig_Rejects covers the three TTLs that must be refused:
// zero TTL, negative TTL, and 25 hours (one past the 24h cap). The
// acceptance twin for each limit (1ns just above zero, 24h just below
// the cap) lives in TestValidateConfig_NanosecondFloor and
// TestValidateConfig_Accepts; the two checks together pin both sides
// of every boundary the validator enforces.
func TestValidateConfig_Rejects(t *testing.T) {
	// Each case names the rule that must refuse it, never only the value
	// echoed back: "got 0s" would still match if the cap check fired
	// instead, or if a later change reworded the rule.
	cases := []struct {
		name string
		ttl  time.Duration
		want string
	}{
		{"zero", 0, "ttl must be positive, got 0s"},
		{"negative", -time.Second, "ttl must be positive, got -1s"},
		{"25 hours", 25 * time.Hour, "ttl must be at most 24h0m0s, got 25h0m0s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateConfig(Config{TTL: c.ttl})
			if err == nil {
				t.Errorf("validateConfig(TTL=%s) = nil, want error", c.ttl)
				return
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("validateConfig(TTL=%s) = %q, want error containing %q", c.ttl, err, c.want)
			}
		})
	}
}

// TestValidateConfig_Accepts covers the boundary that must be allowed:
// exactly 24 hours is at the cap, not past it. Anything past it has its
// own case above.
func TestValidateConfig_Accepts(t *testing.T) {
	if err := validateConfig(Config{TTL: 24 * time.Hour}); err != nil {
		t.Errorf("TTL=24h: validateConfig = %v, want nil", err)
	}
}

// TestValidateConfig_NanosecondFloor: the smallest positive TTL that
// is allowed. time.Duration is an int64 nanosecond count on every
// platform, so there is no positive value between 0 and 1ns; 1ns is
// the tightest acceptance case next to the zero rejection, and it
// pins the floor validateConfig must accept.
func TestValidateConfig_NanosecondFloor(t *testing.T) {
	if err := validateConfig(Config{TTL: time.Nanosecond}); err != nil {
		t.Errorf("TTL=1ns: validateConfig = %v, want nil", err)
	}
}

// TestNew_RejectsInvalidConfig: the public New path must wrap any
// validateConfig failure as ErrInvalidConfig so callers can distinguish
// startup errors from runtime errors.
func TestNew_RejectsInvalidConfig(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, 25 * time.Hour} {
		_, err := New(newFakeProvider(t), Config{TTL: ttl})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(TTL=%s) = %v, want ErrInvalidConfig", ttl, err)
		}
	}
}

// TestNew_AcceptsValidConfig: every value validateConfig accepts must be
// accepted by New too, including the 24-hour boundary.
func TestNew_AcceptsValidConfig(t *testing.T) {
	for _, ttl := range []time.Duration{time.Nanosecond, time.Minute, time.Hour, 24 * time.Hour} {
		if _, err := New(newFakeProvider(t), Config{TTL: ttl}); err != nil {
			t.Errorf("New(TTL=%s) = %v, want nil", ttl, err)
		}
	}
}

// TestApplyDefaults_IsPassThrough pins the "TTL is not a pointer" rule
// of this package: applyDefaults does NOT fill zero TTL with the default,
// because zero TTL is rejected by validateConfig as a meaningless value.
// Filling it would silently turn a caller bug into a 1-hour token, exactly
// the failure mode this test exists to prevent. The 1-hour default is
// reached via the no-Config path in New, not via applyDefaults.
func TestApplyDefaults_IsPassThrough(t *testing.T) {
	if got := applyDefaults(Config{}).TTL; got != 0 {
		t.Errorf("applyDefaults(Config{}).TTL = %s, want 0 (zero must reach validateConfig, not be silently filled)", got)
	}
	if got := applyDefaults(DefaultConfig()).TTL; got != time.Hour {
		t.Errorf("applyDefaults(DefaultConfig()).TTL = %s, want 1h", got)
	}
	if got := applyDefaults(Config{TTL: 30 * time.Minute}).TTL; got != 30*time.Minute {
		t.Errorf("applyDefaults({30m}).TTL = %s, want 30m (explicit value must survive)", got)
	}
}
