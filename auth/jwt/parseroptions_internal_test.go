package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// The parser options are the whole of the claim validation — there is no
// hand-written check for exp, iss or aud, so deleting an option silently
// removes a control. Each of these survived being deleted with the suite green,
// because every other test builds a well-formed token.

const (
	optIssuer   = "issuer.example"
	optAudience = "aud.example"
	optSubject  = "0192f0c1-0000-7000-8000-000000000000"
)

type signer struct {
	priv ed25519.PrivateKey
	keys map[string]ed25519.PublicKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signer{priv: priv, keys: map[string]ed25519.PublicKey{"k1": pub}}
}

// sign builds an access token from a claim set the caller can bend.
func (s signer) sign(t *testing.T, mutate func(*gjwt.RegisteredClaims)) string {
	t.Helper()
	now := time.Now()
	reg := gjwt.RegisteredClaims{
		Issuer:    optIssuer,
		Subject:   optSubject,
		Audience:  gjwt.ClaimStrings{optAudience},
		IssuedAt:  gjwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
		ID:        "0192f0c1-0000-7000-8000-000000000001", // a UUIDv7: since #443 the jti shape is checked first
	}
	mutate(&reg)
	str, err := signToken(&accessClaims[map[string]any]{RegisteredClaims: reg, Type: tokenTypeAccess}, s.priv, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return str
}

func (s signer) verify(t *testing.T, tokenStr string) error {
	t.Helper()
	_, err := verifyAccessToken[map[string]any](tokenStr, s.keys, time.Now(), optIssuer, optAudience, 0)
	return err
}

// A token with no exp never expires. WithExpirationRequired is the only thing
// that refuses one.
func TestVerifyAccessToken_refusesATokenWithNoExpiry(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, func(c *gjwt.RegisteredClaims) { c.ExpiresAt = nil })

	err := s.verify(t, tok)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("a token with no exp claim = %v, want ErrTokenInvalid; it would never expire", err)
	}
	// mapJWTError collapses the reason, so the acceptance twin is what
	// shows the refusal was the missing claim: the same token with an exp
	// verifies. Until 2026-09-25 the fixture's jti was "jti", which #443's
	// shape check refused first, so this test stayed green with
	// WithExpirationRequired deleted.
	if err := s.verify(t, s.sign(t, func(*gjwt.RegisteredClaims) {})); err != nil {
		t.Fatalf("the same token with an exp: %v, want accepted", err)
	}
}

// A token with iat in the future is refused; the same token issued now is
// accepted.
func TestVerifyAccessToken_refusesATokenIssuedInTheFuture(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, func(c *gjwt.RegisteredClaims) {
		c.IssuedAt = gjwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	})
	if err := s.verify(t, tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("a token issued in the future = %v, want ErrTokenInvalid", err)
	}
	if err := s.verify(t, s.sign(t, func(*gjwt.RegisteredClaims) {})); err != nil {
		t.Fatalf("the same token issued now: %v, want accepted", err)
	}
}

func TestVerifyAccessToken_refusesAnExpiredToken(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, func(c *gjwt.RegisteredClaims) {
		c.ExpiresAt = gjwt.NewNumericDate(time.Now().Add(-time.Hour))
	})

	err := s.verify(t, tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got: %v", err)
	}
}

// Issuer and audience are what stop a token minted by the same key for a
// different service being replayed here.
func TestVerifyAccessToken_refusesAnotherServicesIssuer(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, func(c *gjwt.RegisteredClaims) { c.Issuer = "other.example" })

	if err := s.verify(t, tok); err == nil {
		t.Fatal("a token issued by another service must be refused")
	}
}

func TestVerifyAccessToken_refusesAnotherServicesAudience(t *testing.T) {
	s := newSigner(t)
	tok := s.sign(t, func(c *gjwt.RegisteredClaims) { c.Audience = gjwt.ClaimStrings{"other.example"} })

	if err := s.verify(t, tok); err == nil {
		t.Fatal("a token addressed to another audience must be refused")
	}
}

// The length cap refuses an oversized token before any parsing, so a hostile
// caller cannot make the parser chew through megabytes.
//
// The oversized token has to be otherwise *valid*. My first version passed a
// string of filler, which the parser rejects as malformed whether or not the
// cap exists — so deleting the cap left the test green. Padding a properly
// signed token past the limit is what makes the cap the only thing that can
// refuse it.
func (s signer) oversizedButValid(t *testing.T) string {
	t.Helper()
	now := time.Now()
	tok, err := signToken(&accessClaims[map[string]any]{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    optIssuer,
			Subject:   optSubject,
			Audience:  gjwt.ClaimStrings{optAudience},
			IssuedAt:  gjwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			ID:        "0192f0c1-0000-7000-8000-000000000001", // a UUIDv7: since #443 the jti shape is checked first
		},
		Type:  tokenTypeAccess,
		Extra: map[string]any{"padding": strings.Repeat("a", maxTokenLen)},
	}, s.priv, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(tok) <= maxTokenLen {
		t.Fatalf("fixture is only %d bytes, needs to exceed %d", len(tok), maxTokenLen)
	}
	return tok
}

func TestVerifyAccessToken_refusesAnOversizedToken(t *testing.T) {
	s := newSigner(t)

	err := s.verify(t, s.oversizedButValid(t))
	if !errors.Is(err, ErrTokenOversized) {
		t.Fatalf("want ErrTokenOversized for a valid token over %d bytes, got: %v", maxTokenLen, err)
	}
}

func TestVerifyRefreshToken_refusesAnOversizedToken(t *testing.T) {
	s := newSigner(t)

	_, err := verifyRefreshToken(s.oversizedButValid(t), s.keys, time.Now(), optIssuer, optAudience, 0)
	if !errors.Is(err, ErrTokenOversized) {
		t.Fatalf("want ErrTokenOversized for a valid token over %d bytes, got: %v", maxTokenLen, err)
	}
}
