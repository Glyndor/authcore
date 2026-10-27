package exchange

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDecodeErrorsExcludeResponseValues(t *testing.T) {
	const canary = "9876543210987654321098765432109876543210"
	for _, body := range []string{
		`{"access_token":"at","token_type":"Bearer","expires_in":` + canary + `}`,
		`{"access_token":` + canary + `,"token_type":"Bearer"}`,
		`{"` + canary + `":1,"expires_in":1e999}`,
		`{"access_token":?}`,
	} {
		t.Run(body, func(t *testing.T) {
			p := params()
			p.Secret = canary
			tok, err := Do(context.Background(), respond(200, body), p, canary, canary)
			if tok != nil || !errors.Is(err, errExchange) {
				t.Fatalf("Do = %v, %v; want no tokens and exchange error", tok, err)
			}
			for current := err; current != nil; current = errors.Unwrap(current) {
				for _, value := range []string{canary, "1e999", "?"} {
					if strings.Contains(current.Error(), value) {
						t.Errorf("decode error contains response value %q: %v", value, current)
					}
				}
			}
		})
	}
}
