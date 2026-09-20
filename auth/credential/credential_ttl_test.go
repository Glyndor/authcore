package credential

// TTL and expiry tests. The clock is replaced via c.clock = clock.Fixed(...)
// so every test in this file is deterministic without sleeping.

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

// TestVerify_WithinTTLSucceeds covers the happy path with non-zero elapsed
// time: the token must still verify as long as elapsed <= TTL.
func TestVerify_WithinTTLSucceeds(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Pin the clock to issuedAt + TTL/2: well inside the window.
	c.clock = clock.Fixed(epoch.Add(30 * time.Minute))
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); err != nil {
		t.Errorf("verify at TTL/2: %v", err)
	}
	// And at exactly TTL (boundary inclusive on the inside).
	c.clock = clock.Fixed(epoch.Add(time.Hour))
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); err != nil {
		t.Errorf("verify at exactly TTL: %v", err)
	}
}

// TestVerify_OneNanosecondPastTTLExpires pins the exact failure bound of
// the TTL: a token issued for 1 hour, verified one nanosecond
// past that hour, must return ErrExpired. Driven by a fixed clock, no
// real sleep.
func TestVerify_OneNanosecondPastTTLExpires(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.clock = clock.Fixed(epoch.Add(time.Hour + time.Nanosecond))
	err = c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("1ns past TTL: got %v, want ErrExpired", err)
	}
}

// TestVerify_FarFutureExpires covers the future-leeway guard: an
// issuedAt more than a minute in the future is treated as expired
// (a clock running backwards must not extend a token's
// life). Two minutes future, well past the one-minute skew window.
func TestVerify_FarFutureExpires(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.clock = clock.Fixed(epoch)
	future := epoch.Add(2 * time.Minute)
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, future); !errors.Is(err, ErrExpired) {
		t.Errorf("issuedAt 2min in the future: got %v, want ErrExpired", err)
	}
}

// TestVerify_JustInsideFutureSkewSucceeds is the converse: an issuedAt
// within the 1-minute future-skew window must still verify. The window
// is "leeway", not "rejection".
func TestVerify_JustInsideFutureSkewSucceeds(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.clock = clock.Fixed(epoch)
	// 30s in the future is inside the 1-minute skew window.
	future := epoch.Add(30 * time.Second)
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, future); err != nil {
		t.Errorf("issuedAt 30s in the future: %v", err)
	}
}

// TestVerify_OneMinutePastFutureSkewExpires pins the exact boundary: the
// leeway is exactly 1 minute; 1 minute + 1 nanosecond in the future is
// past it.
func TestVerify_OneMinutePastFutureSkewExpires(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.clock = clock.Fixed(epoch)
	future := epoch.Add(time.Minute + time.Nanosecond)
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, future); !errors.Is(err, ErrExpired) {
		t.Errorf("issuedAt 1min+1ns in the future: got %v, want ErrExpired", err)
	}
}

// TestVerify_MatchCheckedBeforeExpiry documents the order Verify applies
// the two checks: a wrong hash always reports ErrInvalidCredential, and
// only a right hash that has aged past TTL reports ErrExpired. This is
// the "same generic message to the user" hook the doc requires: a caller
// who returns the same body for both errors must never reveal which one
// fired, so the constant-time comparison must run first and the expiry
// branch must never observe a wrong hash.
func TestVerify_MatchCheckedBeforeExpiry(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.clock = clock.Fixed(epoch.Add(2 * time.Hour))

	// Right hash, past TTL -> ErrExpired.
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); !errors.Is(err, ErrExpired) {
		t.Errorf("right-hash + past-TTL: got %v, want ErrExpired", err)
	}
	// Wrong hash, past TTL -> ErrInvalidCredential (match fails first).
	if err := c.Verify("reset", "alice@example.com", issued.Token, "deadbeef", epoch); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("wrong-hash + past-TTL: got %v, want ErrInvalidCredential", err)
	}
}

// TestVerify_ZeroIssuedAtExpires protects callers who forget to store
// issuedAt. The zero time is roughly year 1, so every Verify sees it
// as billions of years past expiry. That is the correct outcome; the
// caller must store issuedAt.
func TestVerify_ZeroIssuedAtExpires(t *testing.T) {
	c := newCred(t, Config{TTL: time.Hour})
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	err = c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, time.Time{})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("zero issuedAt: got %v, want ErrExpired", err)
	}
}

// TestVerify_DefaultTTLMatchesDefaultConfig guards the documented
// default: a Credential built with no Config gets a 1-hour TTL.
func TestVerify_DefaultTTLMatchesDefaultConfig(t *testing.T) {
	c := newCred(t) // no Config
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Just inside the default 1-hour window.
	c.clock = clock.Fixed(epoch.Add(59 * time.Minute))
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); err != nil {
		t.Errorf("default TTL: verify at 59m failed: %v", err)
	}
	// Past it.
	c.clock = clock.Fixed(epoch.Add(61 * time.Minute))
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); !errors.Is(err, ErrExpired) {
		t.Errorf("default TTL: verify at 61m: got %v, want ErrExpired", err)
	}
}
