package issue_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func newRig[T any](t *testing.T, cfg jwttest.Config) *jwttest.Rig[T] {
	t.Helper()
	return jwttest.NewRig[T](jwttest.NewKeys(t), cfg)
}

func TestCreateTokens_returnsNonEmptyPair(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if pair.AccessTokenExpiresAt.IsZero() {
		t.Error("AccessTokenExpiresAt is zero")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if pair.RefreshTokenExpiresAt.IsZero() {
		t.Error("RefreshTokenExpiresAt is zero")
	}
	if pair.RefreshTokenHash == "" {
		t.Error("RefreshTokenHash is empty")
	}
}

func TestCreateTokens_invalidSubjectReturnsError(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	cases := []string{
		"",
		"not-a-uuid",
		"123",
		"0191b432-b5a7-7c4f-b2e6",               // too short
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e00001", // too long
		"550e8400-e29b-11d4-a716-446655440000",  // v1 — rejected
		"550e8400-e29b-31d4-a716-446655440000",  // v3 — rejected
		"550e8400-e29b-41d4-a716-446655440000",  // v4 — rejected
		"550e8400-e29b-61d4-a716-446655440000",  // v6 — rejected
	}
	for _, tc := range cases {
		_, err := j.CreateTokens(tc, struct{}{})
		if !errors.Is(err, jwterr.ErrInvalidSubject) {
			t.Errorf("subject %q: expected ErrInvalidSubject, got %v", tc, err)
		}
	}
}

func TestCreateTokens_uppercaseUUIDIsNormalised(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	upper := "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0000"
	pair, err := j.CreateTokens(upper, struct{}{})
	if err != nil {
		t.Fatalf("uppercase UUID v7 should be accepted, got %v", err)
	}

	c, _ := j.VerifyAccessToken(pair.AccessToken)
	if c.Subject != strings.ToLower(upper) {
		t.Errorf("Subject = %q, want lowercase %q", c.Subject, strings.ToLower(upper))
	}
}

func TestCreateTokens_validUUIDVersionsAreAccepted(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())

	cases := []string{
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e4c5a", // v7 lowercase
		"0191B432-B5A7-7C4F-B2E6-7A3F1D2E4C5A", // v7 uppercase
	}
	for _, tc := range cases {
		if _, err := j.CreateTokens(tc, struct{}{}); err != nil {
			t.Errorf("subject %q: unexpected error %v", tc, err)
		}
	}
}

func TestCreateTokens_subjectPreservedInAccessToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042", struct{}{})

	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if c.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042" {
		t.Errorf("Subject = %q, want %q", c.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042")
	}
}

func TestCreateTokens_issuerPreservedInClaims(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Issuer = "my-service"
	j := newRig[struct{}](t, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	c, _ := j.VerifyAccessToken(pair.AccessToken)
	if c.Issuer != "my-service" {
		t.Errorf("Issuer = %q, want %q", c.Issuer, "my-service")
	}
}

func TestCreateTokens_accessAndRefreshTokensAreDifferent(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	if pair.AccessToken == pair.RefreshToken {
		t.Error("AccessToken and RefreshToken must not be equal")
	}
}

func TestCreateTokens_consecutiveCallsProduceUniqueRefreshTokens(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	p1, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	p2, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	if p1.RefreshToken == p2.RefreshToken {
		t.Error("consecutive CreateTokens calls must not produce equal refresh tokens")
	}
	if p1.RefreshTokenHash == p2.RefreshTokenHash {
		t.Error("consecutive CreateTokens calls must not produce equal refresh hashes")
	}
}

func TestCreateTokens_accessTokenExpiryIsCorrect(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	c, _ := j.VerifyAccessToken(pair.AccessToken)

	want := jwttest.Epoch.Add(5 * time.Minute)
	if !c.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", c.ExpiresAt.Time, want)
	}
}

func TestCreateTokens_expiryFieldsMatchConfig(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	cfg.RefreshTokenTTL = 12 * time.Hour
	j := newRig[struct{}](t, cfg)

	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	wantAccess := jwttest.Epoch.Add(5 * time.Minute)
	if !pair.AccessTokenExpiresAt.Equal(wantAccess) {
		t.Errorf("AccessTokenExpiresAt = %v, want %v", pair.AccessTokenExpiresAt, wantAccess)
	}

	wantRefresh := jwttest.Epoch.Add(12 * time.Hour)
	if !pair.RefreshTokenExpiresAt.Equal(wantRefresh) {
		t.Errorf("RefreshTokenExpiresAt = %v, want %v", pair.RefreshTokenExpiresAt, wantRefresh)
	}
}

func TestCreateTokens_refreshHashMatchesHashRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	got := j.HashRefreshToken(pair.RefreshToken)
	if got != pair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(RefreshToken) = %q, want %q", got, pair.RefreshTokenHash)
	}
}

func TestCreateTokens_sessionIDIsUUIDv7(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if pair.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
	id := pair.SessionID
	if len(id) != 36 {
		t.Fatalf("SessionID length = %d, want 36", len(id))
	}
	if id[14] != '7' {
		t.Errorf("SessionID version digit = %q, want '7'", id[14])
	}
	if id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b' {
		t.Errorf("SessionID variant nibble = %q, want 8/9/a/b", id[19])
	}
}

func TestCreateTokens_consecutiveSessionIDsAreUnique(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	p1, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	p2, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	if p1.SessionID == p2.SessionID {
		t.Error("consecutive CreateTokens calls must not produce equal SessionIDs")
	}
}

func TestCreateTokens_audienceEmbeddedInAccessToken(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newRig[struct{}](t, cfg)
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience = %v, want [https://api.example.com]", c.Audience)
	}
}

// TestCreate_accessTokenExpiresAtMatchesClaim pins that the time
// reported on the TokenPair is exactly what the signed exp claim carries.
// golang-jwt truncates NumericDate to whole seconds, so a TTL with sub-second
// precision must be truncated the same way at issuance, or the operator sees
// a time the verifier does not.
func TestCreateTokens_accessTokenExpiresAtMatchesClaim(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.AccessTokenTTL = 5*time.Minute + 999*time.Nanosecond
	j := newRig[struct{}](t, cfg)

	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}
	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if !pair.AccessTokenExpiresAt.Equal(c.ExpiresAt.Time) {
		t.Errorf("AccessTokenExpiresAt = %v, want %v (the signed exp claim)",
			pair.AccessTokenExpiresAt, c.ExpiresAt.Time)
	}
}
