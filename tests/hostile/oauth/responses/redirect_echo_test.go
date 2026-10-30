package responses_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_RedirectErrorsDoNotEchoCredentials(t *testing.T) {
	const secret, code, verifier, bearer = "secret+canary-7401", "code+canary-8523", "verifier+canary-9635", "bearer+canary-1742"
	for _, operation := range []string{"exchange", "userinfo"} {
		values := []string{secret, code, verifier}
		if operation == "userinfo" {
			values = []string{bearer}
		}
		for _, value := range values {
			for _, target := range []string{"https://idp.example/fail", "http://idp.example/fail", "https://other.example/fail"} {
				t.Run(operation+"/"+value+"/"+target, func(t *testing.T) {
					requests := 0
					cause := errors.New("upstream unavailable")
					hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
						requests++
						if r.URL.Path == "/fail" {
							return nil, cause
						}
						response := hostiletest.MemResponse(r, 307, nil)
						response.Header.Set("Location", target+"?echo="+url.QueryEscape(value))
						return response, nil
					})}
					var err error
					sentinel := oauth.ErrExchange
					if operation == "exchange" {
						c := hostiletest.TokenClient(t, "https://idp.example/token", func(cfg *oauth.Config) { cfg.HTTPClient = hc; cfg.ClientSecret = secret })
						got, e := c.Exchange(hostiletest.Ctx(t), code, verifier)
						err = e
						if got != nil {
							t.Fatal("redirect failure returned tokens")
						}
					} else {
						sentinel = oauth.ErrUserInfo
						c := hostiletest.UserinfoClient(t, "https://idp.example/userinfo", func(cfg *oauth.Config) { cfg.HTTPClient = hc })
						got, e := c.UserInfo(hostiletest.Ctx(t), bearer)
						err = e
						if got != nil {
							t.Fatal("redirect failure returned a profile")
						}
					}
					if !errors.Is(err, sentinel) {
						t.Fatalf("wrong refusal: %v", err)
					}
					allowed := target == "https://idp.example/fail"
					if allowed && (requests != 2 || !errors.Is(err, cause)) {
						t.Fatalf("allowed redirect lost cause or second hop: requests=%d err=%v", requests, err)
					}
					if !allowed && requests != 1 {
						t.Fatalf("prohibited redirect followed: %d requests", requests)
					}
					assertCredentialFree(t, err, []string{secret, code, verifier, bearer})
				})
			}
		}
	}
}

func assertCredentialFree(t *testing.T, err error, credentials []string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, value := range credentials {
		for _, spelling := range []string{value, url.QueryEscape(value), url.PathEscape(value)} {
			if strings.Contains(err.Error(), spelling) {
				t.Fatal("error chain repeats a credential")
			}
		}
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			assertCredentialFree(t, cause, credentials)
		}
	case interface{ Unwrap() error }:
		assertCredentialFree(t, e.Unwrap(), credentials)
	}
}
