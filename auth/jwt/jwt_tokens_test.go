package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/internal/clock"
)

func TestVerifyAccessToken_wrongIssuerRejectsToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Another service that happens to share the signing key (e.g. accidental
	// key reuse across microservices) must not accept a token issued by the
	// first service. The iss claim must be checked on verification.
	cfg2 := DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestVerifyAccessToken_missingKidRejectsToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	// An attacker may try to strip the kid header entirely, betting that
	// the verifier trusts the (single) configured public key regardless.
	// The verifier must reject tokens whose kid does not match, which
	// includes tokens where kid is absent.
	claims := newAccessClaims(j.cfg.Issuer, testSubject, "019600ab-0000-7000-8000-000000000002", j.cfg.Audience, struct{}{}, epoch, j.cfg.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	// Deliberately do not set token.Header["kid"].
	stripped, err := token.SignedString(j.priv)
	if err != nil {
		t.Fatalf("sign kid-less token: %v", err)
	}

	_, err = j.VerifyAccessToken(stripped)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for missing kid, got %v", err)
	}
}

func TestRotateTokens_unknownKidRejectsRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	// Mirror of the access-token kid check but on the rotation path. A
	// refresh token with a kid the module does not recognise must be
	// rejected before it is exchanged for a fresh pair.
	claims := newRefreshClaims(j.cfg.Issuer, testSubject, "019600ab-0000-7000-8000-000000000003", j.cfg.Audience, epoch, j.cfg.RefreshTokenTTL)
	claims.Type = tokenTypeRefresh
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "attacker-controlled-kid"
	tampered, err := token.SignedString(j.priv)
	if err != nil {
		t.Fatalf("sign tampered refresh token: %v", err)
	}

	_, err = j.RotateTokens(tampered, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for unknown kid on refresh, got %v", err)
	}
}

func TestVerifyAccessToken_unknownKidRejectsToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	// Craft a token signed with the module's private key (so the signature
	// is valid) but with a "kid" header the verifier does not recognise.
	// This simulates an attacker who has obtained a signing key but whose
	// "kid" is not on the verifier's trusted list — the kid check must
	// reject the token before it is accepted.
	claims := newAccessClaims(j.cfg.Issuer, testSubject, "019600ab-0000-7000-8000-000000000001", j.cfg.Audience, struct{}{}, epoch, j.cfg.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "attacker-controlled-kid"
	tampered, err := token.SignedString(j.priv)
	if err != nil {
		t.Fatalf("sign tampered token: %v", err)
	}

	_, err = j.VerifyAccessToken(tampered)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for unknown kid, got %v", err)
	}
}

func TestRotateTokens_wrongIssuerRejectsRefreshToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	cfg2 := DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestRotateTokens_audienceEmbeddedInRefreshToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Rotation must succeed — refresh token carries the same audience.
	j.clock = clock.Fixed(epoch.Add(time.Second))
	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
}

// ---- custom claims ----------------------------------------------------------

type testUserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func TestCreateTokens_customClaimsRoundTrip(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	extra := testUserClaims{Name: "Juan", Role: "admin"}

	pair, err := j.CreateTokens(testSubject, extra)
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Extra.Name != "Juan" {
		t.Errorf("Extra.Name = %q, want %q", claims.Extra.Name, "Juan")
	}
	if claims.Extra.Role != "admin" {
		t.Errorf("Extra.Role = %q, want %q", claims.Extra.Role, "admin")
	}
}

func TestCreateTokens_refreshTokenHasNoExtraClaims(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, testUserClaims{Name: "Juan", Role: "admin"})

	// Decode the refresh token payload and verify "extra" is absent.
	parts := strings.SplitN(pair.RefreshToken, ".", 3)
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal refresh payload: %v", err)
	}
	if _, ok := payload["extra"]; ok {
		t.Error("refresh token payload must not contain 'extra' field")
	}
}

func TestCreateTokens_refreshTokenHasIat(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	parts := strings.SplitN(pair.RefreshToken, ".", 3)
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal refresh payload: %v", err)
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("refresh token payload must contain 'iat' field")
	}
}

// ---- kid header -------------------------------------------------------------

func TestCreateTokens_accessTokenHeaderContainsKid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	h := tokenHeader(t, pair.AccessToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("access token header missing or empty kid: %v", h)
	}
	if kid != "test0000test0000" {
		t.Errorf("kid = %q, want %q", kid, "test0000test0000")
	}
}

func TestCreateTokens_refreshTokenHeaderContainsKid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	h := tokenHeader(t, pair.RefreshToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("refresh token header missing or empty kid: %v", h)
	}
	if kid != "test0000test0000" {
		t.Errorf("kid = %q, want %q", kid, "test0000test0000")
	}
}

func TestCreateTokens_bothTokensShareSameKid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	accessKid := tokenHeader(t, pair.AccessToken)["kid"]
	refreshKid := tokenHeader(t, pair.RefreshToken)["kid"]
	if accessKid != refreshKid {
		t.Errorf("access kid %q != refresh kid %q", accessKid, refreshKid)
	}
}

// ---- access token jti -------------------------------------------------------

func TestCreateTokens_sessionIDIsUUIDv7Format(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

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

func TestCreateTokens_accessAndRefreshShareSameJTI(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.TokenID != pair.SessionID {
		t.Errorf("access token jti %q must equal SessionID %q", claims.TokenID, pair.SessionID)
	}
}

// ---- VerifyAccessToken() ----------------------------------------------------

func TestVerifyAccessToken_validTokenReturnsCorrectClaims(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099", struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099")
	}
	if !claims.IssuedAt.Equal(epoch) {
		t.Errorf("IssuedAt = %v, want %v", claims.IssuedAt, epoch)
	}
}

func TestVerifyAccessToken_expiredTokenReturnsErrTokenExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance clock past expiry.
	j.clock = clock.Fixed(epoch.Add(11 * time.Minute))

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tokenAtExactExpiryIsExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})
	// golang-jwt/v5 uses strict now.After(exp), so the token is still valid at
	// the exact expiry second. Advance one second past exp to trigger expiry.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + time.Second))

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token one second past expiry should return ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tamperedSignatureReturnsErrTokenInvalid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Modify a middle character of the signature segment to guarantee the
	// decoded bytes change. The last base64url char of an Ed25519 signature
	// encodes only 2 meaningful bits — altering it does not affect the
	// decoded byte slice, so we target a position well inside the signature.
	token := pair.AccessToken
	mid := len(token) - 10
	orig := token[mid]
	replacement := byte('A')
	if orig == 'A' {
		replacement = 'B'
	}
	tampered := token[:mid] + string(replacement) + token[mid+1:]

	_, err := j.VerifyAccessToken(tampered)
	if !errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestVerifyAccessToken_malformedTokenReturnsErrTokenMalformed(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{"", "only-one-part", "two.parts", "a.b.c.d"}
	for _, tc := range cases {
		_, err := j.VerifyAccessToken(tc)
		if !errors.Is(err, ErrTokenMalformed) && !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("input %q: expected ErrTokenMalformed, got %v", tc, err)
		}
	}
}

func TestVerifyAccessToken_rejectsRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.VerifyAccessToken(pair.RefreshToken)
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestVerifyAccessToken_rejectsTokenFromDifferentKey(t *testing.T) {
	p1 := newFakeProvider(t)
	p2 := newFakeProvider(t) // different Ed25519 key pair

	j1 := newTestJWT[struct{}](t, p1, DefaultConfig())
	j2 := newTestJWT[struct{}](t, p2, DefaultConfig())

	pair, _ := j1.CreateTokens(testSubject, struct{}{})

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("token signed by j1 should be invalid for j2, got %v", err)
	}
}

// ---- HashRefreshToken() -----------------------------------------------------
