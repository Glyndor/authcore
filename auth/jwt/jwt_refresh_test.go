package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Jaro-c/authcore/internal/clock"
)

func TestHashRefreshToken_isDeterministic(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	h1 := j.HashRefreshToken(pair.RefreshToken)
	h2 := j.HashRefreshToken(pair.RefreshToken)
	if h1 != h2 {
		t.Errorf("HashRefreshToken is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashRefreshToken_differentTokensDifferentHashes(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})

	if j.HashRefreshToken(p1.RefreshToken) == j.HashRefreshToken(p2.RefreshToken) {
		t.Error("different refresh tokens must produce different HMAC digests")
	}
}

func TestHashRefreshToken_differentSecretsDifferentHashes(t *testing.T) {
	j1 := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	// Sign a token with j1's key, hash it with both modules' secrets.
	pair, _ := j1.CreateTokens(testSubject, struct{}{})

	h1 := j1.HashRefreshToken(pair.RefreshToken)
	h2 := j2.HashRefreshToken(pair.RefreshToken)

	// Different HMAC secrets must produce different digests.
	if h1 == h2 {
		t.Error("same token hashed with different secrets should produce different results")
	}
}

// ---- RotateTokens() ---------------------------------------------------------

func TestRotateTokens_returnsNewPairForSameSubject(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007", struct{}{})

	newPair, err := j.RotateTokens(old.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}

	claims, _ := j.VerifyAccessToken(newPair.AccessToken)
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007" {
		t.Errorf("Subject after rotation = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007")
	}
}

func TestRotateTokens_newTokensDifferFromOld(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance clock by 1 second so the issued-at differs.
	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(old.RefreshToken, struct{}{})

	if newPair.AccessToken == old.AccessToken {
		t.Error("new AccessToken must differ from old AccessToken")
	}
	if newPair.RefreshToken == old.RefreshToken {
		t.Error("new RefreshToken must differ from old RefreshToken")
	}
	if newPair.RefreshTokenHash == old.RefreshTokenHash {
		t.Error("new RefreshTokenHash must differ from old RefreshTokenHash")
	}
}

func TestRotateTokens_expiredRefreshTokenReturnsErrTokenExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshTokenTTL = 24 * time.Hour
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance past refresh token TTL.
	j.clock = clock.Fixed(epoch.Add(25 * time.Hour))

	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRotateTokens_rejectsAccessToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.RotateTokens(pair.AccessToken, struct{}{})
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestRotateTokens_rejectsTamperedToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	rt := pair.RefreshToken
	midRT := len(rt) - 10
	origRT := rt[midRT]
	replacementRT := byte('A')
	if origRT == 'A' {
		replacementRT = 'B'
	}
	tampered := rt[:midRT] + string(replacementRT) + rt[midRT+1:]
	_, err := j.RotateTokens(tampered, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestRotateTokens_newHashMatchesHashRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(pair.RefreshToken, struct{}{})

	got := j.HashRefreshToken(newPair.RefreshToken)
	if got != newPair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(new token) = %q, want %q", got, newPair.RefreshTokenHash)
	}
}

func TestRotateTokens_preservesSessionID(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	original, _ := j.CreateTokens(testSubject, struct{}{})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	rotated, err := j.RotateTokens(original.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
	if rotated.SessionID != original.SessionID {
		t.Errorf("SessionID changed after rotation: got %q, want %q", rotated.SessionID, original.SessionID)
	}
}

// ---- VerifyRefreshTokenHash() -----------------------------------------------

func TestVerifyRefreshTokenHash_matchesStoredHash(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if !j.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned false for a valid token/hash pair")
	}
}

func TestVerifyRefreshTokenHash_modifiedTokenDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken+"X", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for a modified token")
	}
}

func TestVerifyRefreshTokenHash_modifiedHashDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	badHash := strings.Repeat("0", 64)
	if j.VerifyRefreshTokenHash(pair.RefreshToken, badHash) {
		t.Error("VerifyRefreshTokenHash returned true for a tampered hash")
	}
}

func TestVerifyRefreshTokenHash_emptyTokenDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash("", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for empty token")
	}
}

func TestVerifyRefreshTokenHash_emptyHashDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken, "") {
		t.Error("VerifyRefreshTokenHash returned true for empty stored hash")
	}
}

func TestVerifyRefreshTokenHash_consistentWithHashRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	hash := j.HashRefreshToken(pair.RefreshToken)
	if !j.VerifyRefreshTokenHash(pair.RefreshToken, hash) {
		t.Error("VerifyRefreshTokenHash disagrees with HashRefreshToken for the same input")
	}
}

// ---- ClockSkewLeeway --------------------------------------------------------

func TestNew_negativeLeewayReturnsErrInvalidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = -1 * time.Second

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestVerifyAccessToken_tokenWithinLeewayIsAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance 20 s past expiry — within the 30 s leeway window.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + 20*time.Second))
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("token within leeway should be accepted, got %v", err)
	}
}

func TestVerifyAccessToken_tokenBeyondLeewayIsRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance 31 s past expiry — beyond the leeway window.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + 31*time.Second))
	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token beyond leeway should return ErrTokenExpired, got %v", err)
	}
}

// ---- applyDefaults ----------------------------------------------------------

func TestApplyDefaults_zeroTTLsAreFilledFromDefaults(t *testing.T) {
	cfg := Config{
		Issuer:   "my-service",
		Audience: []string{"my-audience"},
		// AccessTokenTTL and RefreshTokenTTL intentionally zero
	}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() with zero TTLs error = %v", err)
	}
	if j.cfg.AccessTokenTTL != DefaultConfig().AccessTokenTTL {
		t.Errorf("AccessTokenTTL not filled: got %v", j.cfg.AccessTokenTTL)
	}
	if j.cfg.RefreshTokenTTL != DefaultConfig().RefreshTokenTTL {
		t.Errorf("RefreshTokenTTL not filled: got %v", j.cfg.RefreshTokenTTL)
	}
}

func TestApplyDefaults_zeroIssuerIsFilledFromDefaults(t *testing.T) {
	cfg := Config{Audience: []string{"x"}}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if j.cfg.Issuer != DefaultConfig().Issuer {
		t.Errorf("Issuer not filled: got %q", j.cfg.Issuer)
	}
}

func TestApplyDefaults_zeroAudienceIsFilledFromDefaults(t *testing.T) {
	cfg := Config{Issuer: "x"}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(j.cfg.Audience) == 0 {
		t.Error("Audience not filled from defaults")
	}
}

// ---- TestRotateTokens_freshClaimsEmbeddedInNewAccessToken -------------------

func TestRotateTokens_freshClaimsEmbeddedInNewAccessToken(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens(testSubject, testUserClaims{Name: "Juan", Role: "user"})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	fresh := testUserClaims{Name: "Juan", Role: "admin"} // role promoted
	newPair, _ := j.RotateTokens(old.RefreshToken, fresh)

	claims, err := j.VerifyAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Extra.Role != "admin" {
		t.Errorf("Extra.Role after rotation = %q, want %q", claims.Extra.Role, "admin")
	}
}
