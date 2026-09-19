package jwt

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// TestRefreshTokenWithoutRIDStillRotates proves the rid field is a no-op at
// verification time: a refresh token issued before rid existed (RID="") must
// still verify and rotate, and the rotation must mint a refresh token whose
// rid is non-empty. This guards the "omitempty" tag and the fact that
// verifyRefreshToken never inspects rid.
func TestRefreshTokenWithoutRIDStillRotates(t *testing.T) {
	prov := newFakeProvider(t)
	j := newTestJWT[struct{}](t, prov, DefaultConfig())

	claims := newRefreshClaims(
		j.cfg.Issuer,
		testSubject,
		"019600ab-0000-7000-8000-00000000aaaa",
		"", // no rid: the legacy shape, which must still verify
		j.cfg.Audience,
		epoch,
		j.cfg.RefreshTokenTTL,
	)
	legacy, err := signToken(claims, prov.Keys().PrivateKey(), keymanager.KeyID(prov.Keys().PublicKey()))
	if err != nil {
		t.Fatalf("sign legacy refresh token: %v", err)
	}

	if strings.Contains(legacyPayloadJSON(t, legacy), `"rid"`) {
		t.Errorf("legacy token payload JSON contains %q; expected it to be absent", `"rid"`)
	}

	next, err := j.RotateTokens(legacy, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens(legacy) error = %v", err)
	}
	if next.SessionID != claims.ID {
		t.Errorf("rotated SessionID = %q, want %q", next.SessionID, claims.ID)
	}

	rotatedClaims := parseRefreshClaimsForTest(t, j, next.RefreshToken)
	if rotatedClaims.RID == "" {
		t.Error("rotated refresh token has empty RID; expected a fresh random value")
	}
}

// TestGenerateRID pins the contract of generateRID: it returns a base64 raw
// URL-encoded value whose decoded length is exactly 16 bytes, and two calls in
// the same nanosecond produce distinct values.
func TestGenerateRID(t *testing.T) {
	first, err := generateRID()
	if err != nil {
		t.Fatalf("generateRID() first error = %v", err)
	}
	second, err := generateRID()
	if err != nil {
		t.Fatalf("generateRID() second error = %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("decode first RID: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("decoded RID length = %d, want 16", len(decoded))
	}

	if first == second {
		t.Errorf("two consecutive generateRID() calls returned the same value %q", first)
	}
}

// legacyPayloadJSON returns the base64url-decoded payload of a compact JWT, used
// to assert a claim is absent from a legacy token's wire format. The function
// is unexported and lives next to the internal tests that need it.
func legacyPayloadJSON(t *testing.T, tokenStr string) string {
	t.Helper()
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(data)
}

// parseRefreshClaimsForTest verifies a refresh token through the module and
// returns the decoded refreshClaims struct, used by the internal test to
// inspect the rid of a freshly rotated token.
func parseRefreshClaimsForTest(t *testing.T, j *JWT[struct{}], tokenStr string) *refreshClaims {
	t.Helper()
	claims, err := verifyRefreshToken(
		tokenStr,
		j.verifyKeys,
		j.clock.Now(),
		j.cfg.Issuer,
		j.primaryAudience,
		j.cfg.ClockSkewLeeway,
	)
	if err != nil {
		t.Fatalf("verifyRefreshToken: %v", err)
	}
	return claims
}
