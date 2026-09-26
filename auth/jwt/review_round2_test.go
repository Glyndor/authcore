package jwt

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/internal/clock"
)

// Controls the 2026-09-25 review found working but unpinned, and one stored
// format pinned to a known answer.

// The refresh path refuses a token with no exp, and one issued in the
// future, for those reasons. Both verifiers share parserOptions since #473;
// these pin the refresh side on its own.
func TestRotateTokens_refusesMissingExpAndFutureIat(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	now := j.clock.Now()
	jti, err := generateJTI(now)
	if err != nil {
		t.Fatal(err)
	}
	rid, err := generateRID()
	if err != nil {
		t.Fatal(err)
	}
	// mapJWTError collapses the reason into ErrTokenInvalid, so the
	// untouched token rotating below is what shows each refusal was the
	// claim under test.
	for name, mutate := range map[string]func(*refreshClaims){
		"no exp":     func(c *refreshClaims) { c.ExpiresAt = nil },
		"future iat": func(c *refreshClaims) { c.IssuedAt = gjwt.NewNumericDate(now.Add(24 * time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			rc := newRefreshClaims(j.cfg.Issuer, testSubject, jti, rid, j.cfg.Audience, now, j.cfg.RefreshTokenTTL)
			mutate(rc)
			tok, err := signToken(rc, j.priv, j.kid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.RotateTokens(tok, struct{}{}); !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("RotateTokens = %v, want ErrTokenInvalid", err)
			}
		})
	}
	// The same claims untouched rotate.
	rc := newRefreshClaims(j.cfg.Issuer, testSubject, jti, rid, j.cfg.Audience, now, j.cfg.RefreshTokenTTL)
	tok, err := signToken(rc, j.priv, j.kid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.RotateTokens(tok, struct{}{}); err != nil {
		t.Fatalf("the untouched refresh token: %v", err)
	}
}

// The leeway applies to the refresh path: a refresh token verifies up to
// exp + leeway and not past it.
func TestRotateTokens_honoursTheLeeway(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	j.clock = clock.Fixed(pair.RefreshTokenExpiresAt.Add(20 * time.Second))
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("20 s past exp with a 30 s leeway: %v, want accepted", err)
	}
	j.clock = clock.Fixed(pair.RefreshTokenExpiresAt.Add(40 * time.Second))
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("40 s past exp with a 30 s leeway: %v, want ErrTokenExpired", err)
	}
}

// Issuance refuses a pair whose refresh token would exceed the size the
// verifier accepts. The access token is smaller (no extra claims here, but a
// shorter claim set), so an issuer length exists where only the refresh
// token overflows; #443 added the check and nothing exercised it.
func TestCreateTokens_refusesAnOversizedRefreshToken(t *testing.T) {
	long := DefaultConfig()
	long.Issuer = strings.Repeat("i", 5806)
	j := newTestJWT[struct{}](t, newFakeProvider(t), long)
	if _, err := j.CreateTokens(testSubject, struct{}{}); !errors.Is(err, ErrTokenOversized) {
		t.Fatalf("CreateTokens with a 5806-byte issuer = %v, want ErrTokenOversized", err)
	}

	fits := DefaultConfig()
	fits.Issuer = strings.Repeat("i", 5600)
	j = newTestJWT[struct{}](t, newFakeProvider(t), fits)
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens with a 5600-byte issuer: %v, want a pair", err)
	}
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("the refresh token of that pair does not rotate: %v", err)
	}
}

// validateConfig refuses an empty audience on its own. New fills the
// default in first, so the check is unreachable through New and could be
// deleted with the suite green (the shape #463 pinned for apikey).
func TestValidateConfig_refusesAnEmptyAudience(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = nil
	err := validateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("validateConfig with no audience = %v, want a refusal naming it", err)
	}
	cfg.Audience = []string{"https://api.example"}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig with one audience = %v", err)
	}
}

// Known answer: the refresh-token hash is HMAC-SHA256 of the token string
// under the refresh secret, hex encoded. The expected value was computed
// outside Go. A change here silently invalidates every stored refresh hash.
func TestHashRefreshToken_knownAnswer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{keys: &fakeKeys{priv: priv, pub: pub, secret: []byte("0123456789abcdef0123456789abcdef")}}
	j := newTestJWT[struct{}](t, p, DefaultConfig())
	got, err := j.HashRefreshToken("refresh-token-under-test")
	if err != nil {
		t.Fatal(err)
	}
	const want = "b0e155640d4a6669dd817a7229216277c5fc58547e19f00c9eac83de94b6a15f"
	if got != want {
		t.Fatalf("HashRefreshToken = %s, want %s: the stored-hash format changed", got, want)
	}
}
