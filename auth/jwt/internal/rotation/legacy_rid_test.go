package rotation_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/parse"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// TestRefreshTokenWithoutRIDStillRotates proves the rid field is a no-op at
// verification time: a refresh token issued before rid existed (RID="") must
// still verify and rotate, and the rotation must mint a refresh token whose
// rid is non-empty. This guards the "omitempty" tag and the fact that
// parse.Refresh never inspects rid.
func TestRefreshTokenWithoutRIDStillRotates(t *testing.T) {
	prov := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](prov, jwttest.DefaultConfig())

	cl := claims.NewRefresh(
		j.Cfg.Issuer,
		jwttest.Subject,
		"019600ab-0000-7000-8000-00000000aaaa",
		"", // no rid: the legacy shape, which must still verify
		j.Cfg.Audience,
		jwttest.Epoch,
		j.Cfg.RefreshTokenTTL,
	)
	legacy, err := issue.SignToken(cl, prov.Priv, prov.KeyID())
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
	if next.SessionID != cl.ID {
		t.Errorf("rotated SessionID = %q, want %q", next.SessionID, cl.ID)
	}

	rotatedClaims := parseRefreshClaimsForTest(t, j, next.RefreshToken)
	if rotatedClaims.RID == "" {
		t.Error("rotated refresh token has empty RID; expected a fresh random value")
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
// returns the decoded claims.Refresh struct, used by the internal test to
// inspect the rid of a freshly rotated token.
func parseRefreshClaimsForTest(t *testing.T, j *jwttest.Rig[struct{}], tokenStr string) *claims.Refresh {
	t.Helper()
	cl, err := parse.Refresh(
		tokenStr,
		j.Keys,
		j.Now,
		j.Cfg.Issuer,
		j.Cfg.Audience[0],
		j.Cfg.ClockSkewLeeway,
	)
	if err != nil {
		t.Fatalf("parse.Refresh: %v", err)
	}
	return cl
}
