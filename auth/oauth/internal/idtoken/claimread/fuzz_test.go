package claimread

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// FuzzClaimRead decodes arbitrary JSON into a claim set, with and without
// json.Number, and reads the claims the verifier trusts. The property: nothing
// panics, and every reader agrees with a reference that judges the claim as the
// JSON token it was written as: strings by value, numbers by value and kind,
// email_verified true only for the JSON value true or the string "true", and
// the audience as the same strings in the same order.
func FuzzClaimRead(f *testing.F) {
	f.Add([]byte(`{"aud":"c","email_verified":true,"iat":1,"sub":"u"}`))
	f.Add([]byte(`{"aud":["a","b",7,null],"email_verified":"true"}`))
	f.Add([]byte(`{"aud":{"a":"c"},"email_verified":"True","iat":"1"}`))
	f.Add([]byte(`{"aud":[],"email_verified":1,"iat":1e400}`))
	f.Add([]byte(`{"aud":["b","a",7],"email_verified":1,"iat":1,"sub":"user"}`))

	f.Fuzz(func(t *testing.T, doc []byte) {
		var raw referenceClaims
		if json.Unmarshal(doc, &raw) != nil {
			return
		}
		for _, useNumber := range []bool{false, true} {
			dec := json.NewDecoder(bytes.NewReader(doc))
			if useNumber {
				dec.UseNumber()
			}
			var claims gjwt.MapClaims
			if dec.Decode(&claims) != nil {
				continue
			}
			compareClaims(t, claims, raw, useNumber)
		}
	})
}

func compareClaims(t *testing.T, claims gjwt.MapClaims, raw referenceClaims, useNumber bool) {
	t.Helper()
	for _, key := range []string{"sub", "iat", "aud", "email_verified"} {
		if got, want := String(claims, key), raw.String(key); got != want {
			t.Fatalf("String(%q) = %q, want %q", key, got, want)
		}
		gotNum, gotOK := Numeric(claims, key)
		wantNum, wantOK := raw.Numeric(key, useNumber)
		if gotOK != wantOK || (gotOK && !reflect.DeepEqual(gotNum, wantNum)) {
			t.Fatalf("Numeric(%q) = %#v, %v; want %#v, %v", key, gotNum, gotOK, wantNum, wantOK)
		}
		if got, want := Bool(claims, key), raw.Bool(key); got != want {
			t.Fatalf("Bool(%q) = %v, want %v", key, got, want)
		}
	}
	got, want := Audience(claims), raw.Audience()
	if (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Fatalf("Audience = %#v, want %#v", got, want)
	}
}
