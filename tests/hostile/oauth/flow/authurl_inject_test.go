package flow_test

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: whoever controls a value that ends up inside the authorization
// URL (a tenant-supplied redirect URL, a scope list, a client id read from a
// database, a provider endpoint copied from a document). Effect they want: a
// second state, nonce, redirect_uri or code_challenge in the query string, a
// header or a line break in the redirect, or a fragment that swallows the
// parameters. The URL is what the user's browser is sent to, so it is parsed
// here the way a strict independent consumer would.

// securityParams are the parameters the library owns; each must be present
// exactly once.
var securityParams = []string{
	"response_type", "client_id", "redirect_uri", "scope",
	"state", "nonce", "code_challenge", "code_challenge_method",
}

// newOrRefuse builds a client and reports whether the configuration was
// accepted. A refusal is a good outcome for a hostile value; an acceptance
// has to be safe.
func newOrRefuse(mut func(*oauth.Config)) (*oauth.Client, bool) {
	cfg := oauth.Config{
		ClientID:    hostiletest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer: hostiletest.Issuer, AuthURL: "https://idp.example/auth",
			TokenURL: "https://idp.example/token", JWKSURL: "https://idp.example/jwks",
		},
	}
	mut(&cfg)
	c, err := oauth.New(hostiletest.SilentProvider{}, cfg)
	return c, err == nil
}

// checkAuthURL parses r.URL strictly and fails on anything a consumer could
// read differently from what the library meant.
func checkAuthURL(t *testing.T, r *oauth.AuthRequest, wantRedirect, wantClient, wantScope string) url.Values {
	t.Helper()
	for i, b := range []byte(r.URL) {
		if b <= ' ' || b >= 0x7f || b == '\\' {
			t.Fatalf("byte %d of the authorization URL is %q: it is not all printable ASCII\n%s", i, b, r.URL)
		}
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatalf("authorization URL does not parse: %v", err)
	}
	if u.Fragment != "" || strings.Contains(r.URL, "#") {
		t.Fatalf("authorization URL has a fragment, which would swallow the parameters: %s", r.URL)
	}
	q, err := url.ParseQuery(u.RawQuery) // strict: a stray semicolon is an error
	if err != nil {
		t.Fatalf("authorization query is not strictly parseable: %v\n%s", err, u.RawQuery)
	}
	for _, k := range securityParams {
		if len(q[k]) != 1 {
			t.Fatalf("%s appears %d times: %q", k, len(q[k]), q[k])
		}
	}
	for k, want := range map[string]string{
		"redirect_uri": wantRedirect, "client_id": wantClient, "scope": wantScope,
		"state": r.State, "nonce": r.Nonce, "response_type": "code", "code_challenge_method": "S256",
	} {
		if q.Get(k) != want {
			t.Fatalf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if strings.Count(r.URL, r.Verifier) != 0 {
		t.Fatalf("the PKCE verifier is inside the authorization URL: %s", r.URL)
	}
	if strings.Count(r.URL, r.State) != 1 || strings.Count(r.URL, r.Nonce) != 1 {
		t.Fatalf("state or nonce appears more than once in the URL: %s", r.URL)
	}
	return q
}

func TestHostile_AuthURL_redirectURLCannotAddOrBreakParameters(t *testing.T) {
	for name, redirect := range map[string]string{
		"ampersand and hash":          "https://app.example/cb?x=1&state=evil#frag",
		"encoded ampersand":           "https://app.example/cb?a=b%26state%3Devil",
		"nested redirect_uri":         "https://app.example/cb?redirect_uri=https://evil.example",
		"semicolon":                   "https://app.example/cb;state=evil;nonce=evil",
		"space in the query":          "https://app.example/cb?q=a b",
		"percent-encoded newline":     "https://app.example/cb?q=%0d%0aSet-Cookie:%20x=1",
		"raw newline":                 "https://app.example/cb\nstate=evil",
		"raw carriage return":         "https://app.example/cb\r\nSet-Cookie: x=1",
		"nul byte":                    "https://app.example/cb\x00",
		"unicode path and query":      "https://app.example/cb/é?ü=%F0%9F%92%A5&ñ=ß",
		"right-to-left override":      "https://app.example/cb\u202e?x=1",
		"backslash host confusion":    "https://app.example\\@evil.example/cb",
		"userinfo lookalike":          "https://app.example@evil.example/cb",
		"empty fragment":              "https://app.example/cb#",
		"plus and percent":            "https://app.example/cb?a=1+2&b=100%25",
		"very long query":             "https://app.example/cb?" + strings.Repeat("a=b&", 4000),
		"duplicate foreign parameter": "https://app.example/cb?x=1&x=2",
	} {
		t.Run(name, func(t *testing.T) {
			c, accepted := newOrRefuse(func(cfg *oauth.Config) { cfg.RedirectURL = redirect })
			if !accepted {
				return // refusing the value is as good as neutralising it
			}
			r, err := c.AuthCodeURL()
			if err != nil {
				t.Fatal(err)
			}
			q := checkAuthURL(t, r, redirect, hostiletest.ClientID, "openid email profile")
			if len(q) != len(securityParams) {
				t.Fatalf("the redirect URL added parameters: %v", q)
			}
		})
	}
}

func TestHostile_AuthURL_clientIDAndScopesCannotAddOrBreakParameters(t *testing.T) {
	ids := []string{
		"id&state=evil", "id\r\nX-Evil: 1", "id\x00", "id#frag", "id;nonce=evil", "id é ü", "id=1", strings.Repeat("i", 8000),
	}
	for _, id := range ids {
		t.Run("client id", func(t *testing.T) {
			c, accepted := newOrRefuse(func(cfg *oauth.Config) { cfg.ClientID = id })
			if !accepted {
				return
			}
			r, err := c.AuthCodeURL()
			if err != nil {
				t.Fatal(err)
			}
			checkAuthURL(t, r, "https://app.example/cb", id, "openid email profile")
		})
	}
	scopeSets := [][]string{
		{"openid", "a&state=evil"}, {"openid", "a\r\nb"}, {"openid", "100%"}, {"openid", "a+b", "c d"},
		{"openid", "é", "\u202e"}, {"openid", ""}, {"openid", "x#y"}, {"openid", "x;nonce=evil"},
	}
	for _, scopes := range scopeSets {
		t.Run("scopes", func(t *testing.T) {
			c, accepted := newOrRefuse(func(cfg *oauth.Config) { cfg.Scopes = scopes })
			if !accepted {
				return
			}
			r, err := c.AuthCodeURL()
			if err != nil {
				t.Fatal(err)
			}
			checkAuthURL(t, r, "https://app.example/cb", hostiletest.ClientID, strings.Join(scopes, " "))
		})
	}
}

// A provider endpoint that already carries parameters keeps the foreign ones
// intact (Apple needs its response_mode) and loses every copy of the ones the
// library owns, in any spelling a parser will fold together.
func TestHostile_AuthURL_endpointQueryIsMergedNotTrusted(t *testing.T) {
	const base = "https://idp.example/auth"
	for name, endpoint := range map[string]string{
		"repeated security parameters": base + "?state=a&state=b&nonce=a&nonce=b&code_challenge=a&code_challenge=b",
		"percent-encoded names":        base + "?%73tate=evil&n%6Fnce=evil&code%5Fchallenge=evil",
		"downgrade to plain":           base + "?code_challenge_method=plain&code_challenge_method=plain",
		"token flow":                   base + "?response_type=token&response_type=id_token%20token",
		"empty values":                 base + "?state=&nonce=&client_id=&redirect_uri=",
		"semicolon separated":          base + "?a=1;state=evil&b=2;nonce=evil",
		"bare keys":                    base + "?state&nonce&code_challenge",
		"trailing separators":          base + "?&&state=evil&&",
		"scope smuggled":               base + "?scope=admin&scope=openid",
	} {
		t.Run(name, func(t *testing.T) {
			c, accepted := newOrRefuse(func(cfg *oauth.Config) { cfg.Provider.AuthURL = endpoint })
			if !accepted {
				return
			}
			r, err := c.AuthCodeURL()
			if err != nil {
				t.Fatal(err)
			}
			q := checkAuthURL(t, r, "https://app.example/cb", hostiletest.ClientID, "openid email profile")
			if strings.Contains(r.URL, "evil") || q.Get("code_challenge_method") == "plain" {
				t.Fatalf("a value from the endpoint survived: %s", r.URL)
			}
		})
	}

	t.Run("foreign parameters survive, repeated ones included", func(t *testing.T) {
		c, _ := newOrRefuse(func(cfg *oauth.Config) {
			cfg.Provider.AuthURL = base + "?response_mode=form_post&prompt=login&prompt=consent&hd=example.com"
		})
		r, err := c.AuthCodeURL()
		if err != nil {
			t.Fatal(err)
		}
		q := checkAuthURL(t, r, "https://app.example/cb", hostiletest.ClientID, "openid email profile")
		if q.Get("response_mode") != "form_post" || q.Get("hd") != "example.com" || !slices.Equal(q["prompt"], []string{"login", "consent"}) {
			t.Fatalf("the provider's own parameters were altered: %v", q)
		}
	})
	t.Run("the endpoint's host and path are untouched", func(t *testing.T) {
		c, _ := newOrRefuse(func(cfg *oauth.Config) { cfg.RedirectURL = "https://app.example/cb?x=https://evil.example/" })
		r, _ := c.AuthCodeURL()
		u, _ := url.Parse(r.URL)
		if u.Scheme != "https" || u.Host != "idp.example" || u.Path != "/auth" || u.User != nil {
			t.Fatalf("the destination changed: %s", r.URL)
		}
	})
}
