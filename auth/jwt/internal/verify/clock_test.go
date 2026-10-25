package verify_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// The clock is probed at the exact nanosecond around each time claim, for
// every leeway. RFC 7519 section 4.1.4 says the current time MUST be before
// exp, so at exp itself the token is expired; the leeway moves that edge later
// by exactly its length and no further. Issued tokens carry whole seconds, so
// the rig's clock sits on one.
func TestVerifyAccessToken_expiryEdgeIsExactForEveryLeeway(t *testing.T) {
	const ttl = 10 * time.Minute
	for _, leeway := range []time.Duration{0, time.Second, 30 * time.Second, 5 * time.Minute} {
		cfg := jwttest.DefaultConfig()
		cfg.AccessTokenTTL, cfg.ClockSkewLeeway = ttl, leeway
		j := newRig[struct{}](t, cfg)
		pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		edge := jwttest.Epoch.Add(ttl + leeway) // the first instant that is too late
		for _, tc := range []struct {
			at   time.Time
			live bool
		}{
			{jwttest.Epoch, true},
			{edge.Add(-time.Second), true},
			{edge.Add(-time.Nanosecond), true},
			{edge, false},
			{edge.Add(time.Nanosecond), false},
			{edge.Add(time.Second), false},
			{edge.Add(24 * 365 * time.Hour), false},
		} {
			j.Now = tc.at
			_, err := j.VerifyAccessToken(pair.AccessToken)
			if tc.live && err != nil {
				t.Errorf("leeway %s, at exp%+d ns: refused: %v", leeway, tc.at.Sub(edge), err)
			}
			if !tc.live && !errors.Is(err, jwterr.ErrTokenExpired) {
				t.Errorf("leeway %s, at exp%+d ns: %v, want ErrTokenExpired", leeway, tc.at.Sub(edge), err)
			}
		}
	}
}

// A clock that has been set backwards makes a token issued "in the future":
// iat after now. The verifier refuses it past the leeway and accepts it within,
// exactly, for any size of step back.
func TestVerifyAccessToken_clockSteppedBackwardsIsBoundedByTheLeeway(t *testing.T) {
	for _, leeway := range []time.Duration{0, 30 * time.Second} {
		cfg := jwttest.DefaultConfig()
		cfg.ClockSkewLeeway = leeway
		j := newRig[struct{}](t, cfg)
		pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		for _, back := range []time.Duration{time.Nanosecond, time.Second, 29 * time.Second, 30 * time.Second, 31 * time.Second, time.Hour, 30 * 24 * time.Hour} {
			j.Now = jwttest.Epoch.Add(-back)
			_, err := j.VerifyAccessToken(pair.AccessToken)
			withinLeeway := back <= leeway
			if withinLeeway && err != nil {
				t.Errorf("leeway %s, clock %s behind issue: refused: %v", leeway, back, err)
			}
			if !withinLeeway && !errors.Is(err, jwterr.ErrTokenInvalid) {
				t.Errorf("leeway %s, clock %s behind issue: %v, want ErrTokenInvalid", leeway, back, err)
			}
		}
	}
}

// A refresh token obeys the same edges, so a rotation attempted one nanosecond
// after expiry fails and the session cannot be extended by a skewed clock.
func TestRotateTokens_expiryEdgeIsExact(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.RefreshTokenTTL = time.Hour
	j := newRig[struct{}](t, cfg)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	j.Now = jwttest.Epoch.Add(time.Hour - time.Nanosecond)
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Errorf("one nanosecond before expiry: %v", err)
	}
	j.Now = jwttest.Epoch.Add(time.Hour)
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("at expiry: %v, want ErrTokenExpired", err)
	}
}

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
