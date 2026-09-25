package jwt

// Tests for the defensive-copy rules at construction: the audience slice and
// each previous public key must not be aliased to caller memory, the TTL
// floor and the UTF-8 rule for issuer/audience, and the small error-mapping
// mismatch where expiry plus a non-expiry claim should not surface as
// ErrTokenExpired. Each rejection has a fragment-of-message or errors.Is
// assertion; each rejection has an acceptance twin.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// ---- defensive copies at construction ---------------------------------------

// TestNew_clonesAudienceAndPreviousKeys pins that a caller who mutates the
// Audience slice or wipes a PreviousPublicKeys byte slice after New returns
// cannot reach into the module's runtime state. The module must keep its own
// copies.
func TestNew_clonesAudienceAndPreviousKeys(t *testing.T) {
	aud := []string{"https://api.example.com"}
	prevPub, prevPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate previous key: %v", err)
	}
	prevKid := keymanager.KeyID(prevPub) // capture before any wipe

	cfg := DefaultConfig()
	cfg.Audience = aud
	cfg.PreviousPublicKeys = []ed25519.PublicKey{prevPub}

	prov := newFakeProvider(t)
	j, err := New[struct{}](prov, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pin the clock to epoch so the previously-signed token's exp claim is
	// still in the future when we verify it. The default clock is wall time.
	j.clock = clockPinned(epoch)

	// Mutate the caller's slice and the caller's previous-key bytes after
	// construction. The module's own audience must keep its original value.
	aud[0] = "https://other.example.com"
	for i := range prevPub {
		prevPub[i] = 0
	}

	if j.cfg.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience[0] = %q, want %q (caller mutation leaked into the module)",
			j.cfg.Audience[0], "https://api.example.com")
	}

	// Sign a token with the caller's previous private key, then verify it
	// on the module. The module's copy of the previous public key must
	// still verify, despite the caller's wipe.
	prevClaims := newAccessClaims(j.cfg.Issuer, testSubject, "019600ab-0000-7000-8000-000000000077", j.cfg.Audience, struct{}{}, epoch, j.cfg.AccessTokenTTL)
	prevClaims.Type = tokenTypeAccess
	prevTok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, prevClaims)
	prevTok.Header["kid"] = prevKid
	prevSigned, err := prevTok.SignedString(prevPriv)
	if err != nil {
		t.Fatalf("sign previous-key token: %v", err)
	}
	if _, err := j.VerifyAccessToken(prevSigned); err != nil {
		t.Errorf("a token signed under the caller's previous key must still verify, got %v", err)
	}

	// And the module's own freshly-issued token must still verify despite
	// the caller's wipe.
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens after caller mutation must still succeed, got %v", err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("a token issued after caller mutation must still verify, got %v", err)
	}
}

// ---- TTL >= 1 second ---------------------------------------------------------

// TestNew_rejectsSubSecondAccessTTL pins the boundary at one second. Anything
// below would round to a non-positive expiry through golang-jwt's
// NumericDate truncation and issue a token that is already expired.
func TestNew_rejectsSubSecondAccessTTL(t *testing.T) {
	for _, ttl := range []time.Duration{
		time.Nanosecond,
		time.Millisecond,
		999 * time.Millisecond,
	} {
		cfg := DefaultConfig()
		cfg.AccessTokenTTL = ttl
		_, err := New[struct{}](newFakeProvider(t), cfg)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("AccessTokenTTL=%s: expected ErrInvalidConfig, got %v", ttl, err)
		}
	}
}

// TestNew_acceptsOneSecondAccessTTL is the acceptance twin.
func TestNew_acceptsOneSecondAccessTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = time.Second
	cfg.RefreshTokenTTL = 2 * time.Second
	if _, err := New[struct{}](newFakeProvider(t), cfg); err != nil {
		t.Errorf("AccessTokenTTL=1s must be accepted, got %v", err)
	}
}

// ---- valid UTF-8 in issuer and audience --------------------------------------

// TestNew_rejectsInvalidUTF8Issuer pins that a non-UTF-8 issuer cannot reach
// the verification path: it would be replaced by U+FFFD on the way to JSON
// and never match the configured original.
func TestNew_rejectsInvalidUTF8Issuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "\xff"
	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("non-UTF-8 issuer: expected ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error must name UTF-8 as the failure, got %q", err.Error())
	}
}

// TestNew_rejectsInvalidUTF8AudienceEntry is the audience mirror.
func TestNew_rejectsInvalidUTF8AudienceEntry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"valid", "\xff"}
	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("non-UTF-8 audience: expected ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error must name UTF-8 as the failure, got %q", err.Error())
	}
}

// ---- sub-second expiry reports the claim value -------------------------------

// TestCreateTokens_accessTokenExpiresAtMatchesClaim pins that the time
// reported on the TokenPair is exactly what the signed exp claim carries.
// golang-jwt truncates NumericDate to whole seconds, so a TTL with sub-second
// precision must be truncated the same way at issuance, or the operator sees
// a time the verifier does not.
func TestCreateTokens_accessTokenExpiresAtMatchesClaim(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 5*time.Minute + 999*time.Nanosecond
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}
	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if !pair.AccessTokenExpiresAt.Equal(claims.ExpiresAt) {
		t.Errorf("AccessTokenExpiresAt = %v, want %v (the signed exp claim)",
			pair.AccessTokenExpiresAt, claims.ExpiresAt)
	}
}

// ---- combined expiry + non-expiry failures -----------------------------------

// TestVerifyAccessToken_expiredWithInvalidIssuerReturnsErrTokenInvalid pins
// that a token which fails two claim checks (expired and wrong issuer) is
// reported as ErrTokenInvalid, not ErrTokenExpired. A caller that treats
// expiry as "refresh and retry" must not loop on a token whose issuer is
// also wrong.
//
// The fixture: build a module that shares j's signing key but expects a
// different issuer (service-b). Sign a token under j's key whose iss is
// service-a, then advance jB's clock past exp. Both checks fail.
func TestVerifyAccessToken_expiredWithInvalidIssuerReturnsErrTokenInvalid(t *testing.T) {
	cfgA := DefaultConfig()
	cfgA.Issuer = "https://auth.service-a.example.com"
	cfgA.AccessTokenTTL = 10 * time.Minute
	provA := newFakeProvider(t)
	j, err := New[struct{}](provA, cfgA)
	if err != nil {
		t.Fatalf("New service-a: %v", err)
	}
	j.clock = clockPinned(epoch)

	cfgB := DefaultConfig()
	cfgB.Issuer = "https://auth.service-b.example.com"
	cfgB.AccessTokenTTL = 10 * time.Minute
	provB := newFakeProvider(t)
	jB, err := New[struct{}](provB, cfgB)
	if err != nil {
		t.Fatalf("New service-b: %v", err)
	}
	// Hand jB the service-a key so the signature still verifies, isolating
	// the claim check.
	jB.priv = j.priv
	jB.pub = j.pub
	jB.verifyKeys = map[string]ed25519.PublicKey{j.kid: j.pub}
	jB.clock = clockPinned(epoch.Add(11 * time.Minute)) // past exp

	// Build a token whose iss is service-a (wrong for the verifier jB).
	claims := newAccessClaims("https://auth.service-a.example.com", testSubject, "019600ab-0000-7000-8000-000000000088", cfgB.Audience, struct{}{}, epoch, cfgB.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	signed := signAccessClaimsForTest(t, claims, j.priv, j.kid)

	_, err = jB.VerifyAccessToken(signed)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for expired + wrong issuer, got %v", err)
	}
	if errors.Is(err, ErrTokenExpired) {
		t.Errorf("combined failure must NOT surface as ErrTokenExpired (would invite retry loop), got %v", err)
	}
}

// TestVerifyAccessToken_expiredOnlyReturnsErrTokenExpired is the acceptance
// twin: a token whose only failing claim is exp keeps returning ErrTokenExpired.
func TestVerifyAccessToken_expiredOnlyReturnsErrTokenExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	j.clock = clockPinned(epoch.Add(11 * time.Minute))
	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired-only token must return ErrTokenExpired, got %v", err)
	}
}
