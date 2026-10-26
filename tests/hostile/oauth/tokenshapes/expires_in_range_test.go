package tokenshapes_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_TokenResponse_expiresInStaysInRange(t *testing.T) {
	const tenYears = 10 * 365 * 24 * 3600
	cases := []struct {
		raw     string
		want    int
		refused bool
	}{
		{"3600", 3600, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"-9223372036854775808", 0, true},
		{"9223372036854775807", tenYears, false},
		{"315360001", tenYears, false},
	}
	for _, tc := range cases {
		body := hostiletest.TokenBody(map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": "x", "expires_in": "raw:" + tc.raw})
		tok, err := exchangeBody(t, body, nil)
		if tc.refused {
			if !errors.Is(err, oauth.ErrExchange) {
				t.Errorf("expires_in %s: err = %v, want ErrExchange", tc.raw, err)
			}
			continue
		}
		if err != nil || tok.ExpiresIn != tc.want {
			t.Errorf("expires_in %s: got %+v, %v; want %d", tc.raw, tok, err, tc.want)
		}
	}
}
