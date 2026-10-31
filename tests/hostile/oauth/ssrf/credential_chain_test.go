package ssrf_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Guards auth/oauth/internal/redirect/redirect.go:98-114: every hop must
// enforce HTTPS, same origin, and absent userinfo even after an allowed 307.
// Checks exact credentials on both allowed hops; a broken POST replay cannot
// masquerade as successful prevention of the forbidden second hop.
func TestHostile_Token_allowed307CannotAuthorizeAForbidden308(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		for _, destination := range []string{"cross-origin", "userinfo", "downgrade", "same-origin-control"} {
			t.Run(method+"/"+destination, func(t *testing.T) {
				const id, secret = "chain-client:+/ &", "chain-secret:+/ &=unique"
				const code, verifier = "code:+/ &=unique", "verifier:+/ &=unique"
				const callback = "https://app.example/cb"
				var nextHits, finalHits atomic.Int64
				check := func(r *http.Request) {
					t.Helper()
					if r.Method != http.MethodPost {
						t.Errorf("%s: method=%s, want POST", r.URL.Path, r.Method)
					}
					if err := r.ParseForm(); err != nil {
						t.Errorf("parse form: %v", err)
					}
					want := url.Values{
						"grant_type": {"authorization_code"}, "client_id": {id},
						"redirect_uri": {callback}, "code": {code}, "code_verifier": {verifier},
					}
					auth := ""
					if method == "client_secret_post" {
						want.Set("client_secret", secret)
					} else {
						auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
					}
					if !reflect.DeepEqual(r.PostForm, want) {
						t.Errorf("%s: form=%v, want %v", r.URL.Path, r.PostForm, want)
					}
					if got := r.Header.Values("Authorization"); (auth == "" && len(got) != 0) || (auth != "" && !reflect.DeepEqual(got, []string{auth})) {
						t.Errorf("%s: Authorization=%q, want %q", r.URL.Path, got, auth)
					}
				}
				evil, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					// Return a valid response so a missing guard cannot pass via a parse error.
					_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`))
				}))
				src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/token":
						check(r)
						http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
					case "/next":
						nextHits.Add(1)
						check(r)
						location := "/final"
						switch destination {
						case "cross-origin":
							location = named(evil.URL) + "/steal"
						case "userinfo":
							location = "https://injected:password@" + r.Host + "/final"
						case "downgrade":
							location = "http://" + r.Host + "/final"
						}
						http.Redirect(w, r, location, http.StatusPermanentRedirect)
					case "/final":
						finalHits.Add(1)
						check(r)
						_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`))
					default:
						t.Errorf("unexpected path %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				c := hostiletest.TokenClient(t, named(src.URL)+"/token", func(cfg *oauth.Config) {
					cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL = id, secret, callback
					cfg.Provider.AuthMethods = []string{method}
					cfg.HTTPClient = insecureClient()
				})
				tokens, err := c.Exchange(hostiletest.Ctx(t), code, verifier)
				if n := nextHits.Load(); n != 1 {
					t.Fatalf("allowed hop received %d requests, want 1", n)
				}
				if n := evil.Hits.Load(); n != 0 {
					t.Fatalf("forbidden origin received %d requests", n)
				}
				if destination == "same-origin-control" {
					if err != nil || tokens == nil || tokens.AccessToken != "a" {
						t.Fatalf("allowed chain: tokens=%+v err=%v", tokens, err)
					}
					if n := finalHits.Load(); n != 1 {
						t.Fatalf("allowed final hop received %d requests", n)
					}
					return
				}
				reason := map[string]string{"cross-origin": "cross-origin", "userinfo": "carries credentials", "downgrade": "non-https"}[destination]
				if !errors.Is(err, oauth.ErrExchange) || !strings.Contains(err.Error(), reason) {
					t.Fatalf("want redirect policy refusal %q, got %v", reason, err)
				}
				if tokens != nil {
					t.Fatalf("forbidden chain returned tokens: %+v", tokens)
				}
				if n := finalHits.Load(); n != 0 {
					t.Fatalf("forbidden final hop received %d requests", n)
				}
			})
		}
	}
}
