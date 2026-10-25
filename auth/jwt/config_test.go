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

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/internal/clock"
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

	prov := jwttest.NewProvider(t)
	j, err := New[struct{}](prov, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pin the clock to jwttest.Epoch so the previously-signed token's exp claim is
	// still in the future when we verify it. The default clock is wall time.
	j.clock = clock.Fixed(jwttest.Epoch)

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
	prevClaims := claims.NewAccess(j.cfg.Issuer, jwttest.Subject, "019600ab-0000-7000-8000-000000000077", j.cfg.Audience, struct{}{}, jwttest.Epoch, j.cfg.AccessTokenTTL)
	prevClaims.Type = claims.TypeAccess
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
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
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
		_, err := New[struct{}](jwttest.NewProvider(t), cfg)
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
	if _, err := New[struct{}](jwttest.NewProvider(t), cfg); err != nil {
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
	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
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
	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("non-UTF-8 audience: expected ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error must name UTF-8 as the failure, got %q", err.Error())
	}
}

// ---- TTL ceilings and ordering -----------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	_, err := New[struct{}](jwttest.NewProvider(t), DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_negativeTTLReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = -1 * time.Second

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_accessTTLExactlyAtCeilingAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 24 * time.Hour        // exactly at the cap
	cfg.RefreshTokenTTL = 365*24*time.Hour - 1 // any value above access works; keep below its own cap

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if err != nil {
		t.Errorf("TTL exactly at ceiling must be accepted, got %v", err)
	}
}

func TestNew_refreshTTLExactlyAtCeilingAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 15 * time.Minute
	cfg.RefreshTokenTTL = 365 * 24 * time.Hour // exactly at the cap

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if err != nil {
		t.Errorf("refresh TTL exactly at ceiling must be accepted, got %v", err)
	}
}

func TestNew_accessTTLAboveCeilingReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 48 * time.Hour // above 24 h ceiling
	cfg.RefreshTokenTTL = 96 * time.Hour

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLAboveCeilingReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshTokenTTL = 2 * 365 * 24 * time.Hour // above 365-day ceiling

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLShorterThanAccessReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 30 * time.Minute
	cfg.RefreshTokenTTL = 15 * time.Minute // shorter than access

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// ---- ClockSkewLeeway ---------------------------------------------------------

func TestNew_negativeLeewayReturnsErrInvalidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = -1 * time.Second

	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_zeroConfigUsesDefaults(t *testing.T) {
	// jwt.New is variadic: omitting Config must apply safe defaults, matching
	// the zero-config shape of the other modules.
	j, err := New[struct{}](jwttest.NewProvider(t))
	if err != nil {
		t.Fatalf("New without config error = %v", err)
	}
	if j.cfg.AccessTokenTTL != DefaultConfig().AccessTokenTTL {
		t.Errorf("AccessTokenTTL = %s, want default %s", j.cfg.AccessTokenTTL, DefaultConfig().AccessTokenTTL)
	}
	if j.cfg.Issuer != DefaultConfig().Issuer {
		t.Errorf("Issuer = %q, want default %q", j.cfg.Issuer, DefaultConfig().Issuer)
	}
	// And it must actually work end-to-end with no config.
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens error = %v", err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("VerifyAccessToken error = %v", err)
	}
}

func TestNew_emptyAudienceEntryReturnsErrInvalidConfig(t *testing.T) {
	for _, aud := range [][]string{
		{""},
		{"   "},
		{"valid", ""},
	} {
		cfg := DefaultConfig()
		cfg.Audience = aud
		if _, err := New[struct{}](jwttest.NewProvider(t), cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Audience %q: expected ErrInvalidConfig, got %v", aud, err)
		}
	}
}

func TestNew_boundsTheClockSkewLeeway(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = maxClockSkewLeeway
	if _, err := New[struct{}](jwttest.NewProvider(t), cfg); err != nil {
		t.Fatalf("leeway at the ceiling: %v, want accepted", err)
	}
	cfg.ClockSkewLeeway = maxClockSkewLeeway + time.Nanosecond
	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "clock skew leeway must be at most") {
		t.Fatalf("leeway past the ceiling: %v, want ErrInvalidConfig naming the ceiling", err)
	}
}

func TestNew_refusesATypedNilDenylist(t *testing.T) {
	cfg := DefaultConfig()
	var disabled *stubDenylist
	cfg.Denylist = disabled
	_, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "denylist holds a nil") {
		t.Fatalf("typed-nil Denylist: %v, want ErrInvalidConfig", err)
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

// ---- applyDefaults ----------------------------------------------------------

func TestApplyDefaults_zeroTTLsAreFilledFromDefaults(t *testing.T) {
	cfg := Config{
		Issuer:   "my-service",
		Audience: []string{"my-audience"},
		// AccessTokenTTL and RefreshTokenTTL intentionally zero
	}
	j, err := New[struct{}](jwttest.NewProvider(t), cfg)
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
	j, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if j.cfg.Issuer != DefaultConfig().Issuer {
		t.Errorf("Issuer not filled: got %q", j.cfg.Issuer)
	}
}

func TestApplyDefaults_zeroAudienceIsFilledFromDefaults(t *testing.T) {
	cfg := Config{Issuer: "x"}
	j, err := New[struct{}](jwttest.NewProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(j.cfg.Audience) == 0 {
		t.Error("Audience not filled from defaults")
	}
}
