package idtoken_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Guards auth/oauth/internal/idtoken/idtoken.go:96-102 (expiry/issued-at
// validation) and :229 (NumericDate requirement). Range rejection is an
// intended invariant: a failure here records a conversion gap, not permission
// to change production code. Raw numbers reach the verifier without repair.
func TestHostile_IDToken_numericDateExtremesAndBoundaries(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		p := hostiletest.NewMemProvider(hostiletest.StdJWKS(t))
		c := p.BubbleClient(t, nil)
		now := time.Now().Unix()
		for _, field := range []string{"exp", "nbf", "iat"} {
			cases := []struct {
				raw    string
				accept bool
			}{
				{"1e100", false}, {"-1e100", false},
				{"9223372036854775807", false}, {"9223372036854775808", false},
				{"-9223372036854775809", false},
				{"0.000000001", field != "exp"}, {"-0.000000001", false},
				{fmt.Sprint(now), field != "exp"},
				{fmt.Sprint(now - 1), field != "exp"},
				{fmt.Sprint(now + 1), field == "exp"},
				// golang-jwt's default NumericDate precision is one second: positive
				// fractions in the current second truncate to now, including future iat.
				{fmt.Sprintf("%d.5", now), field != "exp"},
				{fmt.Sprintf("%d.999999999", now-1), field != "exp"},
				{fmt.Sprintf("%d.001", now+1), field == "exp"},
			}
			for _, tc := range cases {
				claims := hostiletest.Claims(hostiletest.Nonce, map[string]any{field: json.RawMessage(tc.raw)})
				raw, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				token := signRawReading(t, `{"alg":"RS256","kid":"k1"}`, string(raw))
				// No recover: a conversion panic must fail this test.
				got, err := hostiletest.Verify(t, c, token)
				if tc.accept {
					if err != nil || got == nil {
						t.Errorf("%s=%s: valid NumericDate: claims=%v err=%v", field, tc.raw, got, err)
					}
				} else {
					if !errors.Is(err, oauth.ErrIDTokenInvalid) || got != nil {
						t.Errorf("%s=%s: want ErrIDTokenInvalid and nil claims, got claims=%+v err=%v", field, tc.raw, got, err)
					}
				}
			}
		}
		if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err != nil {
			t.Fatalf("ordinary valid control: %v", err)
		}
	})
}
