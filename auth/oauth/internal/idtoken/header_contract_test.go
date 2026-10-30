package idtoken

import (
	"context"
	"errors"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

func TestVerifyRejectsPresentNonStringKid(t *testing.T) {
	f := newFixture(t)
	for _, kid := range []any{1, true, nil, []string{"k1"}, map[string]any{}} {
		token := gjwt.NewWithClaims(gjwt.SigningMethodES256, goodClaims())
		token.Header["kid"] = kid
		signed, err := token.SignedString(f.key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Verify(context.Background(), f.params(), signed, testNonce)
		if got != nil || !errors.Is(err, errInvalid) {
			t.Errorf("kid %v: claims=%v err=%v", kid, got, err)
		}
	}
}
