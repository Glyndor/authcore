package oauth

import (
	"encoding/json"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// The two claim helpers below have branches that are reachable only when a
// caller hands them a MapClaims with a wrong-typed value. The public
// VerifyIDToken flow can't get there: golang-jwt's WithIssuedAt and
// WithAudience validators reject an iat-as-string or aud-as-number at
// parse time, before our custom checks run. The branches stay alive as a
// second line of defence against future parser changes, so they get direct
// tests here instead.

func TestNumericClaim_typeBranch(t *testing.T) {
	// Every accept path returns (v, true):
	for _, v := range []any{
		float64(1.7e9),
		json.Number("1700000000"),
	} {
		_, ok := numericClaim(gjwt.MapClaims{"iat": v}, "iat")
		if !ok {
			t.Errorf("numericClaim(%v) = (_, false), want (_, true)", v)
		}
	}
	// Every reject path returns (nil, false). The middle ("key absent")
	// branch is already covered by TestVerifyIDToken_requiresIssuedAt in
	// oauth_core_test.go; this case is the wrong-type one that the public
	// flow cannot produce.
	_, ok := numericClaim(gjwt.MapClaims{"iat": "1700000000"}, "iat")
	if ok {
		t.Errorf("numericClaim with a string iat returned ok=true, want false")
	}
}

func TestAudienceClaim_typeBranch(t *testing.T) {
	// String and array paths are already covered by the public flow; the
	// default branch (any other value, including JSON numbers) returns nil,
	// which downstream compares with len() != 1 to produce the rejection.
	if got := audienceClaim(gjwt.MapClaims{"aud": 12345}); got != nil {
		t.Errorf("audienceClaim with a numeric aud = %v, want nil", got)
	}
	if got := audienceClaim(gjwt.MapClaims{"aud": map[string]any{"x": 1}}); got != nil {
		t.Errorf("audienceClaim with an object aud = %v, want nil", got)
	}
}
