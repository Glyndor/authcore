package parse_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// TestCreateTokens_wrongAudienceRejectsToken: a module that expects another
// audience refuses a token issued for this one.
func TestCreateTokens_wrongAudienceRejectsToken(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	keys := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](keys, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Verify with a different audience config but the same keys, so the
	// modules share the signing key and key id. Otherwise an unknown-key
	// rejection would fire before the audience check ever runs.
	cfg2 := jwttest.DefaultConfig()
	cfg2.Audience = []string{"https://other.example.com"}
	j2 := jwttest.NewRig[struct{}](keys, cfg2)

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when audience does not match, got %v", err)
	}
}

// ---- combined expiry + non-expiry failures -----------------------------------

// TestVerifyAccessToken_expiredWithInvalidIssuerReturnsErrTokenInvalid pins
// that a token which fails two claim checks (expired and wrong issuer) is
// reported as ErrTokenInvalid, not ErrTokenExpired. A caller that treats
// expiry as "refresh and retry" must not loop on a token whose issuer is
// also wrong.
//
// The fixture: build a module that shares the signing key but expects a
// different issuer (service-b). Sign a token under that key whose iss is
// service-a, then advance service-b's clock past exp. Both checks fail.
func TestVerifyAccessToken_expiredWithInvalidIssuerReturnsErrTokenInvalid(t *testing.T) {
	keys := jwttest.NewKeys(t)

	cfgB := jwttest.DefaultConfig()
	cfgB.Issuer = "https://auth.service-b.example.com"
	cfgB.AccessTokenTTL = 10 * time.Minute
	// The verifier shares service-a's key so the signature still verifies,
	// isolating the claim check.
	jB := jwttest.NewRig[struct{}](keys, cfgB)
	jB.Now = jwttest.Epoch.Add(11 * time.Minute) // past exp

	// Build a token whose iss is service-a (wrong for the verifier jB).
	cl := claims.NewAccess("https://auth.service-a.example.com", jwttest.Subject, "019600ab-0000-7000-8000-000000000088", cfgB.Audience, struct{}{}, jwttest.Epoch, cfgB.AccessTokenTTL)
	cl.Type = claims.TypeAccess
	signed := jwttest.SignAccess(t, cl, keys.Priv, keys.KeyID())

	_, err := jB.VerifyAccessToken(signed)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for expired + wrong issuer, got %v", err)
	}
	if errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("combined failure must NOT surface as ErrTokenExpired (would invite retry loop), got %v", err)
	}
}

// TestVerifyAccessToken_expiredOnlyReturnsErrTokenExpired is the acceptance
// twin: a token whose only failing claim is exp keeps returning ErrTokenExpired.
func TestVerifyAccessToken_expiredOnlyReturnsErrTokenExpired(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newRig[struct{}](t, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	j.Now = jwttest.Epoch.Add(11 * time.Minute)
	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Errorf("expired-only token must return ErrTokenExpired, got %v", err)
	}
}
