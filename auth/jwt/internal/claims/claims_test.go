package claims_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
)

var now = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

func TestNewAccess_carriesTheRegisteredClaimsAndTheExtra(t *testing.T) {
	c := claims.NewAccess("iss", "sub", "jti", []string{"aud-1", "aud-2"}, map[string]string{"role": "admin"}, now, 5*time.Minute)

	if c.Issuer != "iss" || c.Subject != "sub" || c.ID != "jti" {
		t.Errorf("registered claims = %q %q %q, want iss sub jti", c.Issuer, c.Subject, c.ID)
	}
	if len(c.Audience) != 2 || c.Audience[0] != "aud-1" || c.Audience[1] != "aud-2" {
		t.Errorf("Audience = %v, want both entries in order", c.Audience)
	}
	if !c.IssuedAt.Equal(now) || !c.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Errorf("iat/exp = %v/%v, want now and now+5m", c.IssuedAt.Time, c.ExpiresAt.Time)
	}
	if c.Type != claims.TypeAccess || c.Extra["role"] != "admin" {
		t.Errorf("Type/Extra = %q %v, want access and the extra claims", c.Type, c.Extra)
	}
}

func TestNewRefresh_carriesTheRidAndNoExtra(t *testing.T) {
	c := claims.NewRefresh("iss", "sub", "jti", "rid-1", []string{"aud"}, now, time.Hour)

	if c.Type != claims.TypeRefresh || c.RID != "rid-1" {
		t.Errorf("Type/RID = %q %q, want refresh and rid-1", c.Type, c.RID)
	}
	if !c.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("exp = %v, want now+1h", c.ExpiresAt.Time)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"extra"`) {
		t.Errorf("refresh payload %s must not carry extra", raw)
	}
}

// RID is omitted when empty, which keeps refresh tokens issued before the
// field existed parseable.
func TestNewRefresh_omitsAnEmptyRid(t *testing.T) {
	raw, err := json.Marshal(claims.NewRefresh("iss", "sub", "jti", "", []string{"aud"}, now, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"rid"`) {
		t.Errorf("payload %s carries a rid, want it absent", raw)
	}
}

// The cap is part of the wire contract: issuance refuses what verification
// would refuse.
func TestMaxTokenLen_isEightKiB(t *testing.T) {
	if claims.MaxTokenLen != 8192 {
		t.Errorf("MaxTokenLen = %d, want 8192", claims.MaxTokenLen)
	}
	if claims.TypeAccess == claims.TypeRefresh {
		t.Error("the two token types must differ")
	}
}
