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

const (
	chainID       = "chain-client:+/ &"
	chainSecret   = "chain-secret:+/ &=unique"
	chainCode     = "code:+/ &=unique"
	chainVerifier = "verifier:+/ &=unique"
	chainCallback = "https://app.example/cb"
	chainTokens   = `{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`
)

// Guards auth/oauth/internal/redirect/redirect.go:98-114: every hop must
// enforce HTTPS, same origin, and absent userinfo even after an allowed 307.
// Checks exact credentials on both allowed hops; a broken POST replay cannot
// masquerade as successful prevention of the forbidden second hop.
func TestHostile_Token_allowed307CannotAuthorizeAForbidden308(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		for _, destination := range []string{"cross-origin", "userinfo", "downgrade", "same-origin-control"} {
			t.Run(method+"/"+destination, func(t *testing.T) {
				runCredentialChain(t, method, destination)
			})
		}
	}
}

// chainRequestCheck returns a function that fails the test unless a request
// is the token POST with exactly the credentials the client auth method sends.
func chainRequestCheck(t *testing.T, method string) func(*http.Request) {
	return func(r *http.Request) {
		t.Helper()
		if r.Method != http.MethodPost {
			t.Errorf("%s: method=%s, want POST", r.URL.Path, r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		want := url.Values{
			"grant_type": {"authorization_code"}, "client_id": {chainID},
			"redirect_uri": {chainCallback}, "code": {chainCode}, "code_verifier": {chainVerifier},
		}
		auth := ""
		if method == "client_secret_post" {
			want.Set("client_secret", chainSecret)
		} else {
			auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(chainID)+":"+url.QueryEscape(chainSecret)))
		}
		if !reflect.DeepEqual(r.PostForm, want) {
			t.Errorf("%s: form=%v, want %v", r.URL.Path, r.PostForm, want)
		}
		if got := r.Header.Values("Authorization"); (auth == "" && len(got) != 0) || (auth != "" && !reflect.DeepEqual(got, []string{auth})) {
			t.Errorf("%s: Authorization=%q, want %q", r.URL.Path, got, auth)
		}
	}
}

// secondHop is where /next sends the client: the destination under test.
func secondHop(destination, host, evilURL string) string {
	switch destination {
	case "cross-origin":
		return named(evilURL) + "/steal"
	case "userinfo":
		return "https://injected:password@" + host + "/final"
	case "downgrade":
		return "http://" + host + "/final"
	}
	return "/final"
}

func runCredentialChain(t *testing.T, method, destination string) {
	var nextHits, finalHits atomic.Int64
	check := chainRequestCheck(t, method)
	evil, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return a valid response so a missing guard cannot pass via a parse error.
		_, _ = w.Write([]byte(chainTokens))
	}))
	src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			check(r)
			http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
		case "/next":
			nextHits.Add(1)
			check(r)
			http.Redirect(w, r, secondHop(destination, r.Host, evil.URL), http.StatusPermanentRedirect)
		case "/final":
			finalHits.Add(1)
			check(r)
			_, _ = w.Write([]byte(chainTokens))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	c := hostiletest.TokenClient(t, named(src.URL)+"/token", func(cfg *oauth.Config) {
		cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL = chainID, chainSecret, chainCallback
		cfg.Provider.AuthMethods = []string{method}
		cfg.HTTPClient = insecureClient()
	})
	tokens, err := c.Exchange(hostiletest.Ctx(t), chainCode, chainVerifier)
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
}
