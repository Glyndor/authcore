package responses_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_Exchange_ProviderErrorEchoDoesNotLeakRequestSecrets(t *testing.T) {
	const secret = "client-secret-canary-719"
	const code = "authorization-code-canary-832"
	const verifier = "pkce-verifier-canary-946"
	for _, field := range []string{"error", "error_description"} {
		for _, echoed := range []string{secret, code, verifier} {
			t.Run(field+"/"+echoed, func(t *testing.T) {
				transport := hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if r.Form.Get("client_secret") != secret || r.Form.Get("code") != code || r.Form.Get("code_verifier") != verifier {
						t.Error("fixture did not receive the request secrets")
					}
					body := map[string]string{"error": "invalid_grant", "error_description": "request refused"}
					body[field] = "provider echoed " + echoed
					encoded, err := json.Marshal(body)
					if err != nil {
						return nil, err
					}
					return hostiletest.MemResponse(r, http.StatusOK, encoded), nil
				})
				c := hostiletest.TokenClient(t, "https://idp.example/token", func(cfg *oauth.Config) {
					cfg.HTTPClient = &http.Client{Transport: transport}
					cfg.ClientSecret = secret
					cfg.Provider.AuthMethods = []string{"client_secret_post"}
				})
				got, err := c.Exchange(hostiletest.Ctx(t), code, verifier)
				if got != nil || !errors.Is(err, oauth.ErrExchange) {
					t.Fatalf("error envelope returned tokens or lost ErrExchange: tokens=%v err=%v", got, err)
				}
				for _, value := range []string{secret, code, verifier} {
					if strings.Contains(err.Error(), value) {
						t.Errorf("provider error exposed a request secret: %q", value)
					}
				}
			})
		}
	}
}
