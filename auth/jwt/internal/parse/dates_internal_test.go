package parse

import (
	"errors"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

func TestCheckDates(t *testing.T) {
	at := func(sec int64) *gjwt.NumericDate { return gjwt.NewNumericDate(time.Unix(sec, 0)) }
	cases := []struct {
		name string
		rc   gjwt.RegisteredClaims
		ok   bool
	}{
		{"none", gjwt.RegisteredClaims{}, true},
		{"lower bound", gjwt.RegisteredClaims{IssuedAt: at(minNumericDate)}, true},
		{"upper bound", gjwt.RegisteredClaims{ExpiresAt: at(maxNumericDate)}, true},
		{"before 1970", gjwt.RegisteredClaims{IssuedAt: at(-1)}, false},
		{"after 9999", gjwt.RegisteredClaims{ExpiresAt: at(maxNumericDate + 1)}, false},
		{"wrapped iat", gjwt.RegisteredClaims{IssuedAt: at(-1 << 63)}, false},
		{"wrapped nbf", gjwt.RegisteredClaims{NotBefore: at(-1 << 63)}, false},
	}
	for _, tc := range cases {
		err := checkDates(tc.rc)
		if tc.ok && err != nil {
			t.Errorf("%s: %v, want nil", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, jwterr.ErrTokenInvalid) {
			t.Errorf("%s: %v, want ErrTokenInvalid", tc.name, err)
		}
	}
}
