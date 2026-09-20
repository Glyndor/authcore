package jwt

// Tests for the four behaviour gaps fixed in the same pass: oversized payloads
// at issuance, sub/jti validation after signature, defensive copies of caller
// inputs, and the smaller config / error-mapping mismatches. Each rejection
// has a fragment-of-message or errors.Is assertion (the rule says a bare
// err != nil is never enough); each rejection has an acceptance twin.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// ---- oversized tokens at issuance --------------------------------------------

// TestCreateTokens_rejectsOversizedPayload pins the symmetry between issuance
// and verification: a payload large enough to push the signed token past the
// 8 KiB cap must be rejected at issue time with a message that names the
// limit and the actual size, so the operator does not discover it on the
// next request when the verifier calls the token malformed.
func TestCreateTokens_rejectsOversizedPayload(t *testing.T) {
	j := newTestJWT[string](t, newFakeProvider(t), DefaultConfig())

	huge := strings.Repeat("a", 8192)
	pair, err := j.CreateTokens(testSubject, huge)
	if err == nil {
		t.Fatalf("CreateTokens with an oversized payload must fail, got pair %+v", pair)
	}
	if pair != nil {
		t.Errorf("CreateTokens returned a non-nil pair alongside the error: %+v", pair)
	}
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "8192") {
		t.Errorf("error message must name the 8192 byte limit, got %q", msg)
	}
	if !strings.Contains(msg, "exceeds") {
		t.Errorf("error message must name the failure shape, got %q", msg)
	}
}

// TestCreateTokens_oversizedPayloadJustUnderBoundAccepts is the acceptance
// twin: a payload just under the cap must issue and verify without error.
// The exact boundary depends on header, signature and the other claims, so
// the test picks a small string that is well inside the cap rather than
// probing for the threshold.
func TestCreateTokens_oversizedPayloadJustUnderBoundAccepts(t *testing.T) {
	j := newTestJWT[string](t, newFakeProvider(t), DefaultConfig())

	pair, err := j.CreateTokens(testSubject, strings.Repeat("a", 1024))
	if err != nil {
		t.Fatalf("CreateTokens under the cap must succeed, got %v", err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("a token issued just under the cap must verify, got %v", err)
	}
}

// TestCreateTokens_rejectsOversizedIssuer is the mirror case for the issuer
// string. A long issuer blows the refresh token past the cap, since the
// refresh token does not carry extra claims.
func TestCreateTokens_rejectsOversizedIssuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = strings.Repeat("i", 8192)
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New with oversized issuer must succeed (the cap is checked at issuance), got %v", err)
	}
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err == nil {
		t.Fatalf("CreateTokens with an oversized issuer must fail, got pair %+v", pair)
	}
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got %v", err)
	}
}

// ---- sub and jti validation on the verification path -------------------------

// TestVerifyAccessToken_rejectsMissingSubject pins that an access token whose
// signature, issuer, audience, expiry and type all check out, but whose sub
// claim is empty, is still rejected with ErrTokenInvalid. The denylist must
// not be consulted for a token whose claims fail validation.
func TestVerifyAccessToken_rejectsMissingSubject(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Re-sign the access claims with an empty subject; everything else
	// stays the same, so the only failing claim is sub.
	claims := newAccessClaims(j.cfg.Issuer, "", pair.SessionID, j.cfg.Audience, struct{}{}, epoch, j.cfg.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	signed := signAccessClaimsForTest(t, claims, j.priv, j.kid)

	_, err := j.VerifyAccessToken(signed)
	if !errors.Is(err, ErrTokenInvalid) {
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", claims.Subject, testSubject)
	}
}

// TestVerifyAccessToken_rejectsMalformedSessionID is the jti mirror of the
// missing-subject test. An empty jti is refused before the denylist lookup.
func TestVerifyAccessToken_rejectsMalformedSessionID(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	j.CreateTokens(testSubject, struct{}{}) // we don't need the pair; only the keys

	claims := newAccessClaims(j.cfg.Issuer, testSubject, "", j.cfg.Audience, struct{}{}, epoch, j.cfg.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	signed := signAccessClaimsForTest(t, claims, j.priv, j.kid)

	_, err := j.VerifyAccessToken(signed)
	if !errors.Is(err, ErrTokenInvalid) {
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

	badSubClaims := newRefreshClaims(j.cfg.Issuer, "not-a-uuid", "019600ab-0000-7000-8000-000000000099", "", j.cfg.Audience, epoch, j.cfg.RefreshTokenTTL)
	badSubClaims.Type = tokenTypeRefresh
	badSub := signRefreshClaimsForTest(t, badSubClaims, j.priv, j.kid)

	_, err := j.RotateTokens(badSub, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("rotate with malformed sub: expected ErrTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("error must name sub as the failing claim, got %q", err.Error())
	}

	badJTIClaims := newRefreshClaims(j.cfg.Issuer, testSubject, "not-a-uuid", "", j.cfg.Audience, epoch, j.cfg.RefreshTokenTTL)
	badJTIClaims.Type = tokenTypeRefresh
	badJTI := signRefreshClaimsForTest(t, badJTIClaims, j.priv, j.kid)

	_, err = j.RotateTokens(badJTI, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) {
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Errorf("rotate of a well-formed refresh token must succeed, got %v", err)
	}
}

// ---- helpers ----------------------------------------------------------------

// signAccessClaimsForTest signs accessClaims with the EdDSA method and a kid
// header for verification with module j. Used to construct hand-crafted
// tokens whose only difference from a real one is the claim under test.
func signAccessClaimsForTest[T any](t *testing.T, claims *accessClaims[T], priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign access claims: %v", err)
	}
	return signed
}

// signRefreshClaimsForTest is the refresh-claims mirror of
// signAccessClaimsForTest.
func signRefreshClaimsForTest(t *testing.T, claims *refreshClaims, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign refresh claims: %v", err)
	}
	return signed
}

// clockPinned builds a clock.Fixed at t.
func clockPinned(t time.Time) fixedClock { return fixedClock{t: t} }

// fixedClock is the test-only clock implementation the verification path can
// be pinned to via j.clock = clockPinned(...). It deliberately mirrors the
// shape of clock.Fixed to keep the helper local.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }
