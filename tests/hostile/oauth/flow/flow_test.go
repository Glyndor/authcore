package flow_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: the person at the browser (they can replay a callback, swap a
// code, forge a state) and a hostile or buggy authorization server. Effects
// they want: log in as someone else with a token or code that belongs to

func TestHostile_Flow_aCorrectLoginWorksEndToEnd(t *testing.T) {
	// The control every attack below is measured against.
	c, as := flowRig(t, "s3cr3t", nil)
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	code := as.authorize(t, req.URL)
	tok, err := c.Exchange(hostiletest.Ctx(t), code, req.Verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claimsOut, err := c.VerifyIDToken(hostiletest.Ctx(t), tok.IDToken, req.Nonce)
	if err != nil || claimsOut.Subject != "user-abc" {
		t.Fatalf("VerifyIDToken = %+v, %v", claimsOut, err)
	}
}

func TestHostile_Flow_stateNonceAndVerifierAreUnpredictableAndPerRequest(t *testing.T) {
	c, _ := flowRig(t, "", nil)
	seen := map[string]string{}
	const n = 500
	for range n {
		r, err := c.AuthCodeURL()
		if err != nil {
			t.Fatal(err)
		}
		for kind, v := range map[string]string{"state": r.State, "nonce": r.Nonce, "verifier": r.Verifier} {
			if len(v) < 43 {
				t.Fatalf("%s %q has under 256 bits of entropy", kind, v)
			}
			if strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
				t.Fatalf("%s %q is not base64url", kind, v)
			}
			if prev, dup := seen[v]; dup {
				t.Fatalf("%s repeats the earlier %s %q", kind, prev, v)
			}
			seen[v] = kind
		}
		u, _ := url.Parse(r.URL)
		q := u.Query()
		if q.Get("state") != r.State || q.Get("nonce") != r.Nonce {
			t.Fatal("the URL does not carry the state and nonce it returned")
		}
		sum := sha256.Sum256([]byte(r.Verifier))
		if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("code_challenge_method") != "S256" {
			t.Fatalf("code challenge is not S256 of the verifier: %v", q)
		}
	}
	if len(seen) != 3*n {
		t.Fatalf("expected %d distinct secrets, got %d", 3*n, len(seen))
	}
}

// Whatever sits in the configured values, the authorization URL carries each
// security parameter exactly once and with the value the library generated.
func TestHostile_Flow_configValuesCannotInjectOrOverrideAuthorizationParameters(t *testing.T) {
	hostileID := "id&redirect_uri=https://evil.example&state=evil"
	hostileRedirect := "https://app.example/cb?state=evil&nonce=evil&code_challenge=evil#frag"
	cfgMut := func(c *oauth.Config) {
		c.ClientID = hostileID
		c.RedirectURL = hostileRedirect
		c.Scopes = []string{"openid", "x&response_type=token", "a b\nc", "é"}
		// A pre-seeded authorization URL that tries to pin the values and downgrade PKCE.
		c.Provider.AuthURL = "https://idp.example/auth?state=evil&nonce=evil&code_challenge=evil&code_challenge_method=plain&response_type=token&client_id=evil&redirect_uri=https://evil.example&scope=admin"
	}
	c := hostiletest.OIDCClient(t, "https://idp.example/jwks", cfgMut)
	r, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": hostileID, "redirect_uri": hostileRedirect,
		"scope": "openid x&response_type=token a b\nc é", "state": r.State, "nonce": r.Nonce, "code_challenge_method": "S256",
	}
	for k, v := range want {
		if len(q[k]) != 1 || q.Get(k) != v {
			t.Errorf("%s = %q (x%d), want exactly %q", k, q[k], len(q[k]), v)
		}
	}
	if len(q["code_challenge"]) != 1 || q.Get("code_challenge") == "evil" {
		t.Errorf("code_challenge = %q", q["code_challenge"])
	}
	for k := range q {
		if _, known := want[k]; !known && k != "code_challenge" {
			t.Errorf("unexpected parameter %q = %q", k, q[k])
		}
	}
	if strings.Contains(u.Fragment, "state") {
		t.Errorf("the redirect fragment leaked into the URL fragment: %q", u.Fragment)
	}
}
