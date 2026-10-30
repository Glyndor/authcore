package exchange_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
)

func TestVerifierBoundPrecedesSecretsAndHTTP(t *testing.T) {
	for _, size := range []int{1, 43, 128, 129, 2 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			secrets, requests := 0, 0
			p := params()
			p.SecretFunc = func(context.Context) (string, error) { secrets++; return "secret", nil }
			verifier := strings.Repeat("!", size)
			hc := &http.Client{Transport: stub(func(r *http.Request) (*http.Response, error) {
				requests++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				form, err := url.ParseQuery(string(body))
				if err != nil || form.Get("code_verifier") != verifier {
					t.Fatal("verifier changed in transit")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(okBody))}, nil
			})}
			got, err := exchange.Do(context.Background(), hc, p, "code", verifier)
			if size <= 128 {
				if err != nil || got == nil || secrets != 1 || requests != 1 {
					t.Fatalf("valid verifier: tokens=%v err=%v secrets=%d requests=%d", got, err, secrets, requests)
				}
			} else if got != nil || !errors.Is(err, errExchange) || secrets != 0 || requests != 0 {
				t.Fatalf("oversized verifier: tokens=%v err=%v secrets=%d requests=%d", got, err, secrets, requests)
			}
		})
	}
}
