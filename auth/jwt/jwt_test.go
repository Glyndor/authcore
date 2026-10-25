package jwt

// Facade tests (package jwt, not package jwt_test) so that tests can inject a
// clock.Fixed into the unexported jwt.clock field without exposing time
// control as part of the public API.
//
// The behaviour behind each method is tested where it lives: token issuing in
// internal/issue, verification in internal/verify, rotation in
// internal/rotation, refresh-token hashing in internal/refreshhash and the
// denylist in internal/denylist. These tests pin what only this package can:
// that every method hands those packages the module's own policy, and that
// the sentinels it exports are the ones they return.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/internal/clock"
)

// newTestJWT constructs a JWT[T] with the given config and a fixed clock pinned
// to jwttest.Epoch. The clock can be overridden per-test by assigning j.clock.
func newTestJWT[T any](t *testing.T, p authcore.Provider, cfg Config) *JWT[T] {
	t.Helper()
	j, err := New[T](p, cfg)
	if err != nil {
		t.Fatalf("jwt.New() unexpected error: %v", err)
	}
	j.clock = clock.Fixed(jwttest.Epoch)
	return j
}

// stubDenylist is a programmable Denylist for tests.
type stubDenylist struct {
	revoked     bool
	err         error
	gotJTI      string
	gotCtx      context.Context
	hadDeadline bool
	calls       int
}

func (s *stubDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	s.calls++
	s.gotJTI = jti
	s.gotCtx = ctx
	_, s.hadDeadline = ctx.Deadline()
	return s.revoked, s.err
}

type ctxKey struct{}

func TestNew_implementsModule(t *testing.T) {
	j := newTestJWT[struct{}](t, jwttest.NewProvider(t), DefaultConfig())
	var _ authcore.Module = j // compile-time checked by var _ above, belt+braces here
	if j.Name() != "jwt" {
		t.Errorf("Name() = %q, want %q", j.Name(), "jwt")
	}
}

// The sentinels the package exports are the ones its sub-packages return, so
// errors.Is matches whichever side of the boundary produced the error.
func TestSentinels_areTheOnesTheSubPackagesReturn(t *testing.T) {
	for name, pair := range map[string][2]error{
		"ErrTokenExpired":   {ErrTokenExpired, jwterr.ErrTokenExpired},
		"ErrTokenInvalid":   {ErrTokenInvalid, jwterr.ErrTokenInvalid},
		"ErrTokenMalformed": {ErrTokenMalformed, jwterr.ErrTokenMalformed},
		"ErrTokenOversized": {ErrTokenOversized, jwterr.ErrTokenOversized},
		"ErrWrongTokenType": {ErrWrongTokenType, jwterr.ErrWrongTokenType},
		"ErrInvalidSubject": {ErrInvalidSubject, jwterr.ErrInvalidSubject},
		"ErrTokenRevoked":   {ErrTokenRevoked, jwterr.ErrTokenRevoked},
	} {
		if !errors.Is(pair[0], pair[1]) {
			t.Errorf("%s is not the sentinel the sub-packages return", name)
		}
	}
}

func TestFacade_createVerifyRotateRoundTrip(t *testing.T) {
	j := newTestJWT[testUserClaims](t, jwttest.NewProvider(t), DefaultConfig())

	pair, err := j.CreateTokens(jwttest.Subject, testUserClaims{Name: "Juan", Role: "user"})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}
	if pair.SessionID == "" || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("CreateTokens returned an incomplete pair: %+v", pair)
	}

	got, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if got.Subject != jwttest.Subject || got.TokenID != pair.SessionID || got.Extra.Name != "Juan" {
		t.Errorf("claims = %+v, want the subject, session id and extra the pair was issued with", got)
	}
	if got.Issuer != DefaultConfig().Issuer || len(got.Audience) != 1 || got.Audience[0] != DefaultConfig().Audience[0] {
		t.Errorf("issuer/audience = %q %v, want the configured ones", got.Issuer, got.Audience)
	}
	if !got.IssuedAt.Equal(jwttest.Epoch) || got.IssuedAt.Location() != time.UTC || got.ExpiresAt.Location() != time.UTC {
		t.Errorf("IssuedAt = %v, ExpiresAt = %v, want UTC with iat at the pinned clock", got.IssuedAt, got.ExpiresAt)
	}
	if !got.ExpiresAt.Equal(pair.AccessTokenExpiresAt) {
		t.Errorf("ExpiresAt = %v, want the pair's AccessTokenExpiresAt %v", got.ExpiresAt, pair.AccessTokenExpiresAt)
	}
}

func TestFacade_rotationKeepsTheSessionAndTakesFreshExtraClaims(t *testing.T) {
	j := newTestJWT[testUserClaims](t, jwttest.NewProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(jwttest.Subject, testUserClaims{Name: "Juan", Role: "user"})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}

	j.clock = clock.Fixed(jwttest.Epoch.Add(time.Second))
	rotated, err := j.RotateTokens(pair.RefreshToken, testUserClaims{Name: "Juan", Role: "admin"})
	if err != nil {
		t.Fatalf("RotateTokens: %v", err)
	}
	if rotated.SessionID != pair.SessionID || rotated.RefreshToken == pair.RefreshToken {
		t.Errorf("rotation kept session %q and token %v, want the same session and a new token", rotated.SessionID, rotated.RefreshToken == pair.RefreshToken)
	}
	again, err := j.VerifyAccessToken(rotated.AccessToken)
	if err != nil || again.Extra.Role != "admin" {
		t.Fatalf("the rotated access token = %+v, %v; want the fresh extra claims", again, err)
	}
}

type testUserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func TestFacade_hashesRefreshTokensUnderTheModuleSecret(t *testing.T) {
	j := newTestJWT[struct{}](t, jwttest.NewProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}

	hash, err := j.HashRefreshToken(pair.RefreshToken)
	if err != nil || hash != pair.RefreshTokenHash {
		t.Fatalf("HashRefreshToken = %q, %v; want the pair's RefreshTokenHash %q", hash, err, pair.RefreshTokenHash)
	}
	if !j.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash rejected the pair's own hash")
	}
	if j.VerifyRefreshTokenHash(pair.RefreshToken+"x", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash accepted a different token")
	}
}

func TestFacade_appliesTheConfiguredLifetimesAndLeeway(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, jwttest.NewProvider(t), cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	j.clock = clock.Fixed(jwttest.Epoch.Add(10*time.Minute + 20*time.Second))
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("a token within the leeway should verify, got %v", err)
	}
	j.clock = clock.Fixed(jwttest.Epoch.Add(10*time.Minute + 31*time.Second))
	if _, err := j.VerifyAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("a token beyond the leeway = %v, want ErrTokenExpired", err)
	}
}

func TestFacade_wrongAudienceAndIssuerAreRefused(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	cfg.Issuer = "https://auth.service-a.example.com"
	prov := jwttest.NewProvider(t)
	j := newTestJWT[struct{}](t, prov, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	// Same provider, so the modules share the signing key and key id.
	// Otherwise an unknown-key rejection would fire before the claim checks.
	otherAud := DefaultConfig()
	otherAud.Audience = []string{"https://other.example.com"}
	otherAud.Issuer = cfg.Issuer
	if _, err := newTestJWT[struct{}](t, prov, otherAud).VerifyAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("another audience = %v, want ErrTokenInvalid", err)
	}
	otherIss := DefaultConfig()
	otherIss.Audience = cfg.Audience
	otherIss.Issuer = "https://auth.service-b.example.com"
	if _, err := newTestJWT[struct{}](t, prov, otherIss).VerifyAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("another issuer = %v, want ErrTokenInvalid", err)
	}
}

// ---- denylist wiring --------------------------------------------------------

func TestFacade_denylistRevokesAccessAndRefreshTokens(t *testing.T) {
	stub := &stubDenylist{}
	cfg := DefaultConfig()
	cfg.Denylist = stub
	j := newTestJWT[struct{}](t, jwttest.NewProvider(t), cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("a non-revoked token must verify, got %v", err)
	}
	if !stub.hadDeadline {
		t.Error("the context-less VerifyAccessToken should bound the denylist lookup with a deadline")
	}

	stub.revoked = true
	stub.hadDeadline = false
	if _, err := j.VerifyAccessToken(pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("VerifyAccessToken on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if stub.gotJTI != pair.SessionID {
		t.Errorf("denylist queried jti %q, want SessionID %q", stub.gotJTI, pair.SessionID)
	}
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("RotateTokens on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if !stub.hadDeadline {
		t.Error("the context-less RotateTokens should bound the denylist lookup with a deadline")
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	if _, err := j.VerifyAccessTokenContext(ctx, pair.AccessToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("VerifyAccessTokenContext = %v, want ErrTokenRevoked", err)
	}
	if stub.gotCtx.Value(ctxKey{}) != "request" {
		t.Error("VerifyAccessTokenContext did not pass the caller's context to the denylist")
	}
	if _, err := j.RotateTokensContext(ctx, pair.RefreshToken, struct{}{}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("RotateTokensContext = %v, want ErrTokenRevoked", err)
	}
	if stub.gotCtx.Value(ctxKey{}) != "request" {
		t.Error("RotateTokensContext did not pass the caller's context to the denylist")
	}

	stub.revoked = false
	stub.err = errors.New("store unreachable")
	if _, err := j.VerifyAccessToken(pair.AccessToken); err == nil || !strings.Contains(err.Error(), "denylist lookup") || errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("a failing store = %v, want the wrapped lookup error and no revocation", err)
	}
}

// ---- zero value -------------------------------------------------------------

func TestZeroValueJWT_refusesInsteadOfPanicking(t *testing.T) {
	for name, j := range map[string]*JWT[struct{}]{"zero value": {}, "nil pointer": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := j.CreateTokens(jwttest.Subject, struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("CreateTokens = %v", err)
			}
			if _, err := j.VerifyAccessToken("a.b.c"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyAccessToken = %v", err)
			}
			if _, err := j.VerifyAccessTokenContext(context.Background(), "a.b.c"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyAccessTokenContext = %v", err)
			}
			if _, err := j.RotateTokens("a.b.c", struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("RotateTokens = %v", err)
			}
			if _, err := j.RotateTokensContext(context.Background(), "a.b.c", struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("RotateTokensContext = %v", err)
			}
		})
	}
}

// A token without iat or exp converts to a Claims with zero times rather than
// dereferencing a nil date.
func TestAccessClaimsToClaims_toleratesMissingDates(t *testing.T) {
	cl := claims.NewAccess("iss", jwttest.Subject, "jti", []string{"aud"}, struct{}{}, jwttest.Epoch, time.Minute)
	cl.IssuedAt, cl.ExpiresAt = nil, nil

	got := accessClaimsToClaims(cl)
	if !got.IssuedAt.IsZero() || !got.ExpiresAt.IsZero() {
		t.Errorf("IssuedAt = %v, want the zero time", got.IssuedAt)
	}
	if got.Issuer != "iss" || got.TokenID != "jti" {
		t.Errorf("claims = %+v, want the registered claims carried over", got)
	}
}
