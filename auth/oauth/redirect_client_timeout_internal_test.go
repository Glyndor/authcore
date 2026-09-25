package oauth

import (
	"net/http"
	"testing"
	"time"
)

// TestGuardClient_appliesDefaultTimeoutToZeroTimeoutCaller pins the rule that
// guardClient restores the 10-second bound the default client carries when a
// caller-supplied client arrives with Timeout zero. Without the bound,
// http.Client.Do blocks indefinitely on a hung provider, which is the
// regression that motivated the guard.
func TestGuardClient_appliesDefaultTimeoutToZeroTimeoutCaller(t *testing.T) {
	caller := &http.Client{} // Timeout deliberately zero
	guarded := guardClient(caller)
	if guarded.Timeout != 10*time.Second {
		t.Errorf("a zero-timeout caller must receive the 10-second default, got %v", guarded.Timeout)
	}
	if caller.Timeout != 0 {
		t.Errorf("the caller's client was mutated: Timeout = %v", caller.Timeout)
	}
}

// TestGuardClient_keepsCallerTimeoutWhenNonZero pins the complementary rule:
// a caller who already set a Timeout gets to keep it. The default is only
// applied when the caller's value is zero.
func TestGuardClient_keepsCallerTimeoutWhenNonZero(t *testing.T) {
	caller := &http.Client{Timeout: 3 * time.Second}
	guarded := guardClient(caller)
	if guarded.Timeout != 3*time.Second {
		t.Errorf("a caller-set timeout must be preserved, got %v", guarded.Timeout)
	}
}
