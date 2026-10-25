package claimread

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

func TestNumeric_typeBranch(t *testing.T) {
	// Every accept path returns (v, true):
	for _, v := range []any{
		float64(1.7e9),
		json.Number("1700000000"),
	} {
		_, ok := Numeric(gjwt.MapClaims{"iat": v}, "iat")
		if !ok {
			t.Errorf("Numeric(%v) = (_, false), want (_, true)", v)
		}
	}
	// Every reject path returns (nil, false). The middle ("key absent")
	// branch is already covered by TestVerifyIDToken_requiresIssuedAt in
	// oauth_core_test.go; this case is the wrong-type one that the public
	// flow cannot produce.
	_, ok := Numeric(gjwt.MapClaims{"iat": "1700000000"}, "iat")
	if ok {
		t.Errorf("Numeric with a string iat returned ok=true, want false")
	}
}

func TestAudience_typeBranch(t *testing.T) {
	// String and array paths are already covered by the public flow; the
	// default branch (any other value, including JSON numbers) returns nil,
	// which downstream compares with len() != 1 to produce the rejection.
	if got := Audience(gjwt.MapClaims{"aud": 12345}); got != nil {
		t.Errorf("Audience with a numeric aud = %v, want nil", got)
	}
	if got := Audience(gjwt.MapClaims{"aud": map[string]any{"x": 1}}); got != nil {
		t.Errorf("Audience with an object aud = %v, want nil", got)
	}
}

func TestStringAndBool(t *testing.T) {
	t.Parallel()
	m := gjwt.MapClaims{"s": "x", "n": 1, "t": true, "str-true": "true", "str-no": "yes", "other": 3}
	if String(m, "s") != "x" || String(m, "n") != "" || String(m, "absent") != "" {
		t.Error("String must return only string values")
	}
	for key, want := range map[string]bool{"t": true, "str-true": true, "str-no": false, "other": false, "absent": false} {
		if got := Bool(m, key); got != want {
			t.Errorf("Bool(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestAudienceShapes(t *testing.T) {
	t.Parallel()
	if got := Audience(gjwt.MapClaims{"aud": "a"}); len(got) != 1 || got[0] != "a" {
		t.Errorf("string aud = %v", got)
	}
	if got := Audience(gjwt.MapClaims{"aud": []any{"a", 5, "b"}}); len(got) != 2 {
		t.Errorf("mixed aud = %v, want the two strings", got)
	}
	if got := Audience(gjwt.MapClaims{}); got != nil {
		t.Errorf("absent aud = %v", got)
	}
}
