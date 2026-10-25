package oauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestAuthCodeURL_hasPKCEAndState(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: oauthtest.ClientID, RedirectURL: "https://app/cb", Provider: oauth.Google(),
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if req.State == "" || req.Nonce == "" || req.Verifier == "" {
		t.Fatal("state/nonce/verifier must be set")
	}
	u, _ := url.Parse(req.URL)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             oauthtest.ClientID,
		"code_challenge_method": "S256",
		"state":                 req.State,
		"nonce":                 req.Nonce,
	} {
		if q.Get(k) != want {
			t.Errorf("query %q = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q missing openid", q.Get("scope"))
	}
	if q.Get("code_challenge") == req.Verifier {
		t.Error("challenge must be the hash of the verifier, not the verifier itself")
	}
	// Acceptance pair: the challenge must equal base64url(sha256(verifier)),
	// not just differ from it. A regression that sends the verifier base64'd
	// again (or skips the hash) still differs and would pass a "differs" check
	// alone; pinning the expected value closes that hole.
	sum := sha256.Sum256([]byte(req.Verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if q.Get("code_challenge") != wantChallenge {
		t.Errorf("code_challenge = %q, want %q", q.Get("code_challenge"), wantChallenge)
	}
}

func TestAuthCodeURL_independentPerCall(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	a, _ := c.AuthCodeURL()
	b, _ := c.AuthCodeURL()
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier {
		t.Error("each AuthCodeURL must use fresh secrets")
	}
}

// ---- New validation ---------------------------------------------------------

// ---- VerifyIDToken (the security-critical path) -----------------------------

func TestAuthCodeURL_defaultScopesIncludeOpenID(t *testing.T) {
	// No scopes set -> the OIDC default set is used. The test pins the exact
	// decoded value so a regression that drops a scope or reorders them
	// (e.g. building a different "openid email profile" sequence) does not
	// pass on the "contains openid" check alone.
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google(),
	})
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got, want := u.Query().Get("scope"), "openid email profile"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestAuthCodeURL_callerScopesVerbatim(t *testing.T) {
	// Caller-supplied scopes are used as-is (no openid injected) — required for
	// plain-OAuth2 providers like GitHub.
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.GitHub(),
		Scopes: []string{"read:user", "user:email"},
	})
	req, _ := c.AuthCodeURL()
	if strings.Contains(req.URL, "openid") {
		t.Error("openid must not be injected into caller-supplied scopes")
	}
}

// TestAuthCodeURL_dedupsPreExistingQueryParameters pins the parse-then-Set
// path: when the AuthURL already carries a "state" or "code_challenge"
// parameter, the call must overwrite it instead of producing duplicates
// (which most OIDC servers read as the pre-existing value).
//
// The AuthURL below carries a pre-existing value for every parameter the
// library generates. Each one is asserted to be present exactly once, with
// the fresh value, so a regression that switched from url.Values.Set to
// url.Values.Add, or that left a parameter alone, would either repeat the
// pre-existing string ("plain", "pre", "evil.example", "token") or drop
// the fresh value.
func TestAuthCodeURL_dedupsPreExistingQueryParameters(t *testing.T) {
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: oauthtest.ClientID,
		Scopes:   []string{"openid email profile"},
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth?state=fixed&client_id=cid&code_challenge=pre-existing&code_challenge_method=plain&nonce=pre&redirect_uri=https://evil.example/cb&scope=pre&response_type=token",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
		RedirectURL: "https://app.example/cb",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse AuthCodeURL result: %v", err)
	}
	checks := map[string]string{
		"state":                 req.State,
		"nonce":                 req.Nonce,
		"client_id":             oauthtest.ClientID,
		"code_challenge":        "", // not equal to "pre-existing"; checked below
		"code_challenge_method": "S256",
		"redirect_uri":          "https://app.example/cb",
		"scope":                 "openid email profile",
		"response_type":         "code",
	}
	for key, want := range checks {
		vs := u.Query()[key]
		if len(vs) != 1 {
			t.Errorf("%s: got %d values (%v), want exactly 1", key, len(vs), vs)
			continue
		}
		if key == "code_challenge" {
			if vs[0] == "pre-existing" {
				t.Errorf("%s: must be overwritten, still %q", key, vs[0])
			}
			continue
		}
		if vs[0] != want {
			t.Errorf("%s = %q, want %q", key, vs[0], want)
		}
	}
}

// TestAuthCodeURL_handlesQuerylessAuthURL pins the parse path for a URL
// with no pre-existing query string.
func TestAuthCodeURL_handlesQuerylessAuthURL(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.HasPrefix(req.URL, "https://id.example/auth?") {
		t.Errorf("AuthCodeURL result = %q, want a path followed by ?", req.URL)
	}
}

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
