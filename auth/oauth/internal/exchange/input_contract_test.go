package exchange_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
)

func TestDoAcceptsEightKiBCodeAndRejectsTheNextByteBeforeResolvingSecrets(t *testing.T) {
	t.Parallel()
	for _, size := range []int{8 * 1024, 8*1024 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			secretCalls, requests := 0, 0
			p := params()
			p.SecretFunc = func(context.Context) (string, error) {
				secretCalls++
				return "client-secret", nil
			}
			client := &http.Client{Transport: stub(func(*http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(okBody))}, nil
			})}
			tok, err := exchange.Do(context.Background(), client, p, strings.Repeat("c", size), "verifier")
			if size == 8*1024 {
				if err != nil || tok == nil || secretCalls != 1 || requests != 1 {
					t.Fatalf("code at the limit: tokens=%v, err=%v, secrets=%d, requests=%d", tok, err, secretCalls, requests)
				}
			} else if tok != nil || !errors.Is(err, errExchange) || secretCalls != 0 || requests != 0 {
				t.Fatalf("oversized code: tokens=%v, err=%v, secrets=%d, requests=%d", tok, err, secretCalls, requests)
			}
		})
	}
}

func TestDoPreservesTenYearLifetimeAndClampsOnlyLargerValues(t *testing.T) {
	t.Parallel()
	for _, seconds := range []int{315359999, 315360000, 315360001} {
		body := fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","expires_in":%d}`, seconds)
		tok, err := exchange.Do(context.Background(), respond(200, body, nil), params(), "code", "verifier")
		want := seconds
		if seconds == 315360001 {
			want = 315360000
		}
		if err != nil || tok == nil || tok.ExpiresIn != want {
			t.Fatalf("expires_in %d: tokens=%+v, err=%v; want %d seconds", seconds, tok, err, want)
		}
	}
}

func TestDoNeverRepeatsAnyCredentialInEitherProviderErrorField(t *testing.T) {
	t.Parallel()
	p := params()
	p.Secret = "secret-canary-7401"
	const code, verifier = "code-canary-8523", "verifier-canary-9635"
	for _, credential := range []string{p.Secret, code, verifier} {
		for _, field := range []string{"error", "error_description"} {
			t.Run(credential+"/"+field, func(t *testing.T) {
				errorCode, description := "provider_failure", "refused"
				if field == "error" {
					errorCode = credential
				} else {
					description = credential
				}
				body := fmt.Sprintf(`{"error":%q,"error_description":%q}`, errorCode, description)
				tok, err := exchange.Do(context.Background(), respond(200, body, nil), p, code, verifier)
				if tok != nil || !errors.Is(err, errExchange) {
					t.Fatalf("Do = %+v, %v; want the exchange refusal", tok, err)
				}
				for current := err; current != nil; current = errors.Unwrap(current) {
					if strings.Contains(current.Error(), credential) {
						t.Fatal("provider error repeated a credential")
					}
				}
			})
		}
	}
}

func TestDoNeverCreatesACredentialWhenSanitizingProviderDiagnostics(t *testing.T) {
	t.Parallel()
	p := params()
	p.Secret = "secret?canary-7401"
	for _, field := range []string{"error", "error_description"} {
		t.Run(field, func(t *testing.T) {
			errorCode, description := "provider_failure", "refused"
			if field == "error" {
				errorCode = "secret\ncanary-7401"
			} else {
				description = "secret\ncanary-7401"
			}
			body := fmt.Sprintf(`{"error":%q,"error_description":%q}`, errorCode, description)
			tok, err := exchange.Do(context.Background(), respond(200, body, nil), p, "code", "verifier")
			if tok != nil || !errors.Is(err, errExchange) {
				t.Fatalf("Do = %+v, %v; want the exchange refusal", tok, err)
			}
			if strings.Contains(err.Error(), p.Secret) {
				t.Fatal("sanitizing the provider diagnostic created a credential in the error")
			}
		})
	}
}
