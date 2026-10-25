package issue_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

type testUserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func TestCreateTokens_customClaimsRoundTrip(t *testing.T) {
	j := newRig[testUserClaims](t, jwttest.DefaultConfig())
	extra := testUserClaims{Name: "Juan", Role: "admin"}

	pair, err := j.CreateTokens(jwttest.Subject, extra)
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}

	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if c.Extra.Name != "Juan" {
		t.Errorf("Extra.Name = %q, want %q", c.Extra.Name, "Juan")
	}
	if c.Extra.Role != "admin" {
		t.Errorf("Extra.Role = %q, want %q", c.Extra.Role, "admin")
	}
}

func TestCreateTokens_refreshTokenHasNoExtraClaims(t *testing.T) {
	j := newRig[testUserClaims](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, testUserClaims{Name: "Juan", Role: "admin"})

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
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

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
	keys := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](keys, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	h := jwttest.Header(t, pair.AccessToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("access token header missing or empty kid: %v", h)
	}
	if want := keys.KeyID(); kid != want {
		t.Errorf("kid = %q, want %q", kid, want)
	}
}

func TestCreateTokens_refreshTokenHeaderContainsKid(t *testing.T) {
	keys := jwttest.NewKeys(t)
	j := jwttest.NewRig[struct{}](keys, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	h := jwttest.Header(t, pair.RefreshToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("refresh token header missing or empty kid: %v", h)
	}
	if want := keys.KeyID(); kid != want {
		t.Errorf("kid = %q, want %q", kid, want)
	}
}

func TestCreateTokens_bothTokensShareSameKid(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	accessKid := jwttest.Header(t, pair.AccessToken)["kid"]
	refreshKid := jwttest.Header(t, pair.RefreshToken)["kid"]
	if accessKid != refreshKid {
		t.Errorf("access kid %q != refresh kid %q", accessKid, refreshKid)
	}
}

// ---- access token jti -------------------------------------------------------

func TestCreateTokens_sessionIDIsUUIDv7Format(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

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
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if c.ID != pair.SessionID {
		t.Errorf("access token jti %q must equal SessionID %q", c.ID, pair.SessionID)
	}

	// Rotate to surface the refresh token's jti through the public API.
	// Rotation preserves the session jti, so the new pair's SessionID is
	// the refresh token's jti; comparing both to the original SessionID
	// proves the two tokens share one identifier.
	j.Now = jwttest.Epoch.Add(time.Second)
	rotated, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
	if rotated.SessionID != pair.SessionID {
		t.Errorf("refresh token jti %q must equal SessionID %q", rotated.SessionID, pair.SessionID)
	}
	if c.ID != rotated.SessionID {
		t.Errorf("access token jti %q must equal refresh token jti %q", c.ID, rotated.SessionID)
	}
}
