package verify_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// ---- ClockSkewLeeway --------------------------------------------------------

func TestVerifyAccessToken_tokenWithinLeewayIsAccepted(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Advance 20 s past expiry — within the 30 s leeway window.
	j.Now = jwttest.Epoch.Add(10*time.Minute + 20*time.Second)
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("token within leeway should be accepted, got %v", err)
	}
}

func TestVerifyAccessToken_tokenBeyondLeewayIsRejected(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Advance 31 s past expiry — beyond the leeway window.
	j.Now = jwttest.Epoch.Add(10*time.Minute + 31*time.Second)
	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("token beyond leeway should return ErrTokenExpired, got %v", err)
	}
}
