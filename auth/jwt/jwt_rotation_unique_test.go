package jwt

import (
	"testing"
)

// TestRotateTokens_SameSecondYieldsADifferentToken pins the regression: with the
// clock held still, RotateTokens must return a refresh token whose bytes differ
// from the one presented. The earlier code reproduced the input byte-for-byte
// because iss/sub/aud/jti, iat/exp-second-precision, and the Ed25519 signature
// were all identical within one wall-clock second.
func TestRotateTokens_SameSecondYieldsADifferentToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}

	// Clock held still: do not reassign j.clock after newTestJWT pinned it to
	// epoch. Rotating in the same wall-clock second is the case the regression
	// used to fail.
	next, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}

	if next.RefreshToken == pair.RefreshToken {
		t.Error("next.RefreshToken equals pair.RefreshToken in the same wall-clock second")
	}
	if next.RefreshTokenHash == pair.RefreshTokenHash {
		t.Error("next.RefreshTokenHash equals pair.RefreshTokenHash in the same wall-clock second")
	}
	if next.SessionID != pair.SessionID {
		t.Errorf("SessionID changed after rotation: got %q, want %q", next.SessionID, pair.SessionID)
	}
}

// TestRotateTokens_ThousandRotationsAllDistinct stresses the same-second path:
// 1000 rotations in a single second must produce 1001 distinct refresh tokens
// (the original plus the 1000 rotations) and the SessionID must stay stable
// across every step.
func TestRotateTokens_ThousandRotationsAllDistinct(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}

	seen := make(map[string]struct{}, 1001)
	seen[pair.RefreshToken] = struct{}{}
	current := pair.RefreshToken
	sessionID := pair.SessionID

	for i := 0; i < 1000; i++ {
		next, err := j.RotateTokens(current, struct{}{})
		if err != nil {
			t.Fatalf("RotateTokens() at iteration %d error = %v", i, err)
		}
		if next.SessionID != sessionID {
			t.Fatalf("SessionID changed at iteration %d: got %q, want %q", i, next.SessionID, sessionID)
		}
		seen[next.RefreshToken] = struct{}{}
		current = next.RefreshToken
	}

	if got := len(seen); got != 1001 {
		t.Errorf("distinct refresh tokens = %d, want 1001", got)
	}
}
