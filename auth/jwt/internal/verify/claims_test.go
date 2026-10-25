package verify_test

// Tests for the four behaviour gaps fixed in the same pass: oversized payloads
// at issuance, sub/jti validation after signature, defensive copies of caller
// inputs, and the smaller config / error-mapping mismatches. Each rejection
// has a fragment-of-message or errors.Is assertion (the rule says a bare
// err != nil is never enough); each rejection has an acceptance twin.

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// ---- sub and jti validation on the verification path -------------------------

// TestVerifyAccessToken_rejectsMissingSubject pins that an access token whose
// signature, issuer, audience, expiry and type all check out, but whose sub
// claim is empty, is still rejected with ErrTokenInvalid. The denylist must
// not be consulted for a token whose claims fail validation.
func TestVerifyAccessToken_rejectsMissingSubject(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Re-sign the access claims with an empty subject; everything else
	// stays the same, so the only failing claim is sub.
	cl := claims.NewAccess(j.Cfg.Issuer, "", pair.SessionID, j.Cfg.Audience, struct{}{}, jwttest.Epoch, j.Cfg.AccessTokenTTL)
	cl.Type = claims.TypeAccess
	signed := jwttest.SignAccess(t, cl, j.K.Priv, j.K.KeyID())

	_, err := j.VerifyAccessToken(signed)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for missing subject, got %v", err)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("error must name the failing claim, got %q", err.Error())
	}
	if stub.calls != 0 {
		t.Errorf("denylist must not be consulted when sub fails, got %d calls", stub.calls)
	}
}

// TestVerifyAccessToken_acceptsWellFormedSubject is the acceptance twin: a
// token issued normally must verify without error and surface the right sub.
func TestVerifyAccessToken_acceptsWellFormedSubject(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	cl, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if cl.Subject != jwttest.Subject {
		t.Errorf("Subject = %q, want %q", cl.Subject, jwttest.Subject)
	}
}

// TestVerifyAccessToken_rejectsMalformedSessionID is the jti mirror of the
// missing-subject test. An empty jti is refused before the denylist lookup.
func TestVerifyAccessToken_rejectsMalformedSessionID(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	j.CreateTokens(jwttest.Subject, struct{}{}) // we don't need the pair; only the keys

	cl := claims.NewAccess(j.Cfg.Issuer, jwttest.Subject, "", j.Cfg.Audience, struct{}{}, jwttest.Epoch, j.Cfg.AccessTokenTTL)
	cl.Type = claims.TypeAccess
	signed := jwttest.SignAccess(t, cl, j.K.Priv, j.K.KeyID())

	_, err := j.VerifyAccessToken(signed)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for missing jti, got %v", err)
	}
	if !strings.Contains(err.Error(), "jti") {
		t.Errorf("error must name the failing claim, got %q", err.Error())
	}
	if stub.calls != 0 {
		t.Errorf("denylist must not be consulted when jti fails, got %d calls", stub.calls)
	}
}

// TestRotate_rejectsMalformedClaims is the same rule on the refresh path. A
// refresh token with a malformed subject or jti must be refused before any
// rotation produces a fresh pair, and the denylist (configured here as a
// tripwire) must never be touched.
func TestRotate_rejectsMalformedClaims(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)

	badSubClaims := claims.NewRefresh(j.Cfg.Issuer, "not-a-uuid", "019600ab-0000-7000-8000-000000000099", "", j.Cfg.Audience, jwttest.Epoch, j.Cfg.RefreshTokenTTL)
	badSubClaims.Type = claims.TypeRefresh
	badSub := jwttest.SignRefresh(t, badSubClaims, j.K.Priv, j.K.KeyID())

	_, err := j.RotateTokens(badSub, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("rotate with malformed sub: expected ErrTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("error must name sub as the failing claim, got %q", err.Error())
	}

	badJTIClaims := claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, "not-a-uuid", "", j.Cfg.Audience, jwttest.Epoch, j.Cfg.RefreshTokenTTL)
	badJTIClaims.Type = claims.TypeRefresh
	badJTI := jwttest.SignRefresh(t, badJTIClaims, j.K.Priv, j.K.KeyID())

	_, err = j.RotateTokens(badJTI, struct{}{})
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("rotate with malformed jti: expected ErrTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "jti") {
		t.Errorf("error must name jti as the failing claim, got %q", err.Error())
	}

	if stub.calls != 0 {
		t.Errorf("denylist must never be consulted on the rotate path, got %d calls", stub.calls)
	}
}

// TestRotate_acceptsWellFormedRefreshToken is the acceptance twin: a refresh
// token issued normally rotates into a fresh pair.
func TestRotate_acceptsWellFormedRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Errorf("rotate of a well-formed refresh token must succeed, got %v", err)
	}
}
