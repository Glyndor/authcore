package jwk_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
)

// A key whose member the document writes twice is refused: a JSON reader
// matches a member name to a field without regard to case and writes the field
// again for every member that matches it, so the last one wins and the key
// says two different things to two readers.
func TestDecode_refusesAMemberWrittenTwice(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in string
		ok       bool
	}{
		{"a key with one spelling of each member", `{"kty":"RSA","kid":"k","use":"sig","alg":"RS256","key_ops":["verify"]}`, true},
		{"a member written twice", `{"kty":"RSA","use":"sig","use":"enc"}`, false},
		{"a member written twice in another case", `{"kty":"RSA","use":"sig","USE":"enc"}`, false},
		{"the algorithm written twice in another case", `{"kty":"RSA","alg":"RS256","ALG":"RS512"}`, false},
		{"the operations written twice in another case", `{"kty":"RSA","key_ops":["verify"],"KEY_OPS":["encrypt"]}`, false},
		{"the modulus written twice in another case", `{"kty":"RSA","n":"AQAB","N":"AQAC"}`, false},
		{"a member written once in another case", `{"kty":"RSA","USE":"sig"}`, true},
		{"a member the key does not carry", `{"kty":"RSA","x5t":"a"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, err := jwk.Decode([]byte(tc.in))
			if tc.ok {
				if err != nil {
					t.Fatalf("Decode(%s) = %v, want the key", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Decode(%s) = %+v, want a refusal", tc.in, k)
			}
			if !strings.Contains(err.Error(), "more than once") {
				t.Errorf("Decode(%s) = %v, want the error to name the repeated member", tc.in, err)
			}
		})
	}
}

// A key that is not a JSON object, or whose member holds the wrong kind of
// value, is refused as well.
func TestDecode_refusesAMalformedKey(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`{"kty":42}`, `{"kty":"RSA","n":42}`, `[1,2]`, `{"kty":"RSA"`} {
		if k, err := jwk.Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%s) = %+v, want a refusal", in, k)
		}
	}
}
