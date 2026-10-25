package oauth_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// FuzzAuthCodeURL feeds arbitrary values into the four places a caller's
// configuration reaches the authorization URL: the redirect URL, the client
// id, one scope and the provider endpoint's own query string. The property: if
// New accepts the configuration, the URL it builds is plain ASCII with no
// fragment, parses strictly, carries each parameter the library owns exactly
// once with the value it generated or was given, and carries nothing the
// library does not own except what the endpoint already had.
func FuzzAuthCodeURL(f *testing.F) {
	f.Add("https://app.example/cb", "client", "openid", "response_mode=form_post")
	f.Add("https://app.example/cb?state=evil&x=1#frag", "id&state=evil", "a&nonce=evil", "state=a&state=b")
	f.Add("https://app.example/cb\r\nX: y", "id\r\n", "a b\nc", "code_challenge_method=plain")
	f.Add("https://app.example/cb;state=evil", "é", "%zz", "%73tate=evil")
	f.Add("https://app.example/cb?"+strings.Repeat("a=b&", 50), "", "", "a=1;state=evil")

	owned := []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"}
	f.Fuzz(func(t *testing.T, redirect, clientID, scope, endpointQuery string) {
		c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
			ClientID:    clientID,
			RedirectURL: redirect,
			Scopes:      []string{"openid", scope},
			Provider: oauth.Provider{
				Issuer: "https://idp.example", AuthURL: "https://idp.example/auth?" + endpointQuery,
				TokenURL: "https://idp.example/token", JWKSURL: "https://idp.example/jwks",
			},
		})
		if err != nil {
			return
		}
		r, err := c.AuthCodeURL()
		if err != nil {
			t.Fatalf("AuthCodeURL: %v", err)
		}
		for i := 0; i < len(r.URL); i++ {
			if b := r.URL[i]; b <= ' ' || b >= 0x7f || b == '\\' || b == '#' {
				t.Fatalf("byte %d of the URL is %q: %s", i, b, r.URL)
			}
		}
		u, err := url.Parse(r.URL)
		if err != nil {
			t.Fatalf("the URL does not parse: %v", err)
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			t.Fatalf("the query is not strictly parseable: %v", err)
		}
		want := map[string]string{
			"response_type": "code", "client_id": clientID, "redirect_uri": redirect, "scope": "openid " + scope,
			"state": r.State, "nonce": r.Nonce, "code_challenge_method": "S256",
		}
		for _, k := range owned {
			if len(q[k]) != 1 {
				t.Fatalf("%s appears %d times in %s", k, len(q[k]), r.URL)
			}
			if w, ok := want[k]; ok && q.Get(k) != w {
				t.Fatalf("%s = %q, want %q", k, q.Get(k), w)
			}
		}
		if u.Host != "idp.example" || u.Path != "/auth" {
			t.Fatalf("the destination changed to %s%s", u.Host, u.Path)
		}
	})
}
