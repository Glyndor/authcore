package rotation_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func newRig[T any](t *testing.T, cfg jwttest.Config) *jwttest.Rig[T] {
	t.Helper()
	return jwttest.NewRig[T](jwttest.NewKeys(t), cfg)
}

type testUserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// ---- RotateTokens() ---------------------------------------------------------

func TestRotateTokens_returnsNewPairForSameSubject(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	old, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007", struct{}{})

	newPair, err := j.RotateTokens(old.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}

	cl, _ := j.VerifyAccessToken(newPair.AccessToken)
	if cl.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007" {
		t.Errorf("Subject after rotation = %q, want %q", cl.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007")
	}
}

func TestRotateTokens_newTokensDifferFromOld(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	old, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Advance clock by 1 second so the issued-at differs.
	j.Now = jwttest.Epoch.Add(time.Second)
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
	cfg := jwttest.DefaultConfig()
	cfg.RefreshTokenTTL = 24 * time.Hour
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Advance past refresh token TTL.
	j.Now = jwttest.Epoch.Add(25 * time.Hour)

	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRotateTokens_rejectsAccessToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	_, err := j.RotateTokens(pair.AccessToken, struct{}{})
	if !errors.Is(err, jwterr.ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestRotateTokens_rejectsTamperedToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	rt := pair.RefreshToken
	midRT := len(rt) - 10
	origRT := rt[midRT]
	replacementRT := byte('A')
	if origRT == 'A' {
		replacementRT = 'B'
	}
	tampered := rt[:midRT] + string(replacementRT) + rt[midRT+1:]
	_, err := j.RotateTokens(tampered, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenInvalid) && !errors.Is(err, jwterr.ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestRotateTokens_newHashMatchesHashRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	j.Now = jwttest.Epoch.Add(time.Second)
	newPair, _ := j.RotateTokens(pair.RefreshToken, struct{}{})

	got := j.HashRefreshToken(newPair.RefreshToken)
	if got != newPair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(new token) = %q, want %q", got, newPair.RefreshTokenHash)
	}
}

func TestRotateTokens_preservesSessionID(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	original, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	j.Now = jwttest.Epoch.Add(time.Second)
	rotated, err := j.RotateTokens(original.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
	if rotated.SessionID != original.SessionID {
		t.Errorf("SessionID changed after rotation: got %q, want %q", rotated.SessionID, original.SessionID)
	}
}

// ---- TestRotateTokens_freshClaimsEmbeddedInNewAccessToken -------------------

func TestRotateTokens_freshClaimsEmbeddedInNewAccessToken(t *testing.T) {
	j := newRig[testUserClaims](t, jwttest.DefaultConfig())
	old, _ := j.CreateTokens(jwttest.Subject, testUserClaims{Name: "Juan", Role: "user"})

	j.Now = jwttest.Epoch.Add(time.Second)
	fresh := testUserClaims{Name: "Juan", Role: "admin"} // role promoted
	newPair, _ := j.RotateTokens(old.RefreshToken, fresh)

	cl, err := j.VerifyAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if cl.Extra.Role != "admin" {
		t.Errorf("Extra.Role after rotation = %q, want %q", cl.Extra.Role, "admin")
	}
}
