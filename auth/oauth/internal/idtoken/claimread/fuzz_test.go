package claimread

import (
	"encoding/json"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// FuzzClaimRead decodes arbitrary JSON into a claim set and reads the claims
// the verifier trusts. The property: nothing panics; email_verified is true
// only for the JSON value true or the string "true"; and the audience list
// holds only strings that were in the document.
func FuzzClaimRead(f *testing.F) {
	f.Add([]byte(`{"aud":"c","email_verified":true,"iat":1,"sub":"u"}`))
	f.Add([]byte(`{"aud":["a","b",7,null],"email_verified":"true"}`))
	f.Add([]byte(`{"aud":{"a":"c"},"email_verified":"True","iat":"1"}`))
	f.Add([]byte(`{"aud":[],"email_verified":1,"iat":1e400}`))

	f.Fuzz(func(t *testing.T, doc []byte) {
		var claims gjwt.MapClaims
		if err := json.Unmarshal(doc, &claims); err != nil {
			return
		}
		_ = String(claims, "sub")
		_, _ = Numeric(claims, "iat")

		verified := false
		switch v := claims["email_verified"].(type) {
		case bool:
			verified = v
		case string:
			verified = v == "true"
		}
		if got := Bool(claims, "email_verified"); got != verified {
			t.Fatalf("Bool = %v for %#v", got, claims["email_verified"])
		}

		aud := Audience(claims)
		switch raw := claims["aud"].(type) {
		case string:
			if len(aud) != 1 || aud[0] != raw {
				t.Fatalf("Audience(%q) = %q", raw, aud)
			}
		case []any:
			strs := 0
			for _, a := range raw {
				if _, ok := a.(string); ok {
					strs++
				}
			}
			if len(aud) != strs {
				t.Fatalf("Audience kept %d of %d string members", len(aud), strs)
			}
		default:
			if aud != nil {
				t.Fatalf("Audience of a %T = %q, want nil", raw, aud)
			}
		}
	})
}
