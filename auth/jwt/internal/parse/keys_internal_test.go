package parse

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

func seg(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestCheckObjectKeys(t *testing.T) {
	head := `{"alg":"EdDSA","kid":"k","typ":"JWT"}`
	body := `{"sub":"s","exp":1}`
	cases := []struct {
		name string
		tok  string
		ok   bool
	}{
		{"plain", seg(head) + "." + seg(body) + ".sig", true},
		{"repeated payload key", seg(head) + "." + seg(`{"exp":1,"exp":2}`) + ".sig", false},
		{"payload name in capitals", seg(head) + "." + seg(`{"EXP":1}`) + ".sig", false},
		{"repeated header key", seg(`{"kid":"a","kid":"b"}`) + "." + seg(body) + ".sig", false},
		{"header name in capitals", seg(`{"KID":"a"}`) + "." + seg(body) + ".sig", false},
		{"custom claims in capitals are free", seg(head) + "." + seg(`{"Role":"a"}`) + ".sig", true},
		{"two segments", seg(head) + "." + seg(body), true},
		{"payload is not base64url", seg(head) + ".!!." + "sig", true},
		{"header is not base64url", "!!." + seg(body) + ".sig", true},
	}
	for _, tc := range cases {
		err := checkObjectKeys(tc.tok)
		if tc.ok && err != nil {
			t.Errorf("%s: %v, want nil", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, jwterr.ErrTokenMalformed) {
			t.Errorf("%s: %v, want ErrTokenMalformed", tc.name, err)
		}
	}
}
