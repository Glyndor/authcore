package discovery_test

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: whoever controls what a discovery URL answers (a malicious or
// compromised provider, or a substituted document). Effect they want: a
// Provider whose endpoints or issuer are not the ones the caller asked for,
// so that codes, secrets and tokens flow to, or are validated against, a
// party the caller never chose.

func TestHostile_Discovery_issuerMustBeExactlyTheOneRequested(t *testing.T) {
	type row struct {
		name   string
		issuer func(base string) any // what the document claims
		accept bool
		ask    string // suffix appended to the requested issuer
	}
	rows := []row{
		{name: "control: exact", issuer: func(b string) any { return b }, accept: true},
		{name: "control: requested with a slash, document echoes the slash", ask: "/", issuer: func(b string) any { return b + "/" }, accept: true},
		{name: "requested with a slash, document echoes the trimmed form", ask: "/", issuer: func(b string) any { return b }},
		{name: "requested without a slash, document adds one", issuer: func(b string) any { return b + "/" }},
		{name: "another host", issuer: func(string) any { return "https://accounts.google.com" }},
		{name: "same host, other port", issuer: func(b string) any { return b + "0" }},
		{name: "localhost spelling of the same loopback host", issuer: func(b string) any {
			return strings.Replace(b, "127.0.0.1", "localhost", 1)
		}},
		{name: "extra path", issuer: func(b string) any { return b + "/tenant" }},
		{name: "upper-case scheme", issuer: func(b string) any { return "HTTP" + strings.TrimPrefix(b, "http") }},
		{name: "upper-case host letters in a name", issuer: func(b string) any { return strings.ToUpper(b) }},
		{name: "trailing space", issuer: func(b string) any { return b + " " }},
		{name: "leading space", issuer: func(b string) any { return " " + b }},
		{name: "nul suffix", issuer: func(b string) any { return b + "\x00" }},
		{name: "fullwidth digits", issuer: func(b string) any { return strings.NewReplacer("1", "１", "2", "２").Replace(b) }},
		{name: "empty", issuer: func(string) any { return "" }},
		{name: "missing", issuer: func(string) any { return nil }},
		{name: "number", issuer: func(string) any { return 1 }},
		{name: "array holding the right value", issuer: func(b string) any { return []string{b} }},
		{name: "object", issuer: func(b string) any { return map[string]string{"issuer": b} }},
		{name: "null", issuer: func(string) any { return hostiletest.JSONNull }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			srv := hostiletest.DiscoveryServer(t, func(doc map[string]any, base string) { doc["issuer"] = r.issuer(base) })
			p, err := oauth.Discover(hostiletest.Ctx(t), srv.URL+r.ask, nil)
			if r.accept {
				if err != nil {
					t.Fatalf("control refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a document with issuer %v was accepted for %s: %+v", r.issuer(srv.URL), srv.URL+r.ask, p)
			}
			if !errorsIsDiscovery(err) {
				t.Fatalf("refused, but not as ErrDiscovery: %v", err)
			}
		})
	}
}

func TestHostile_Discovery_endpointsThatMustBeRefused(t *testing.T) {
	bad := map[string]string{
		"plain http to a metadata host": "http://169.254.169.254/latest/meta-data/",
		"plain http to a private host":  "http://10.0.0.5/x",
		"plain http to a real host":     "http://good.example/x",
		"loopback-looking name":         "http://localhost.evil.example/x",
		"loopback prefix name":          "http://127.0.0.1.evil.example/x",
		"userinfo decoy":                "http://127.0.0.1@evil.example/x",
		"ftp":                           "ftp://good.example/x",
		"file":                          "file:///etc/passwd",
		"gopher":                        "gopher://127.0.0.1:70/_x",
		"javascript":                    "javascript:alert(1)",
		"data":                          "data:text/plain,x",
		"scheme-relative":               "//good.example/x",
		"relative":                      "/x",
		"opaque https":                  "https:good.example",
		"https without a host":          "https:///x",
		"https with nothing":            "https://",
		"control character":             "https://good.example/\n",
		"space in the host":             "https://go od.example/",
		"non-numeric port":              "https://good.example:notaport/",
		"not a string":                  "",
	}
	fields := []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"}
	for _, field := range fields {
		for name, v := range bad {
			if name == "not a string" && field == "userinfo_endpoint" {
				continue // an empty userinfo endpoint means "not published"
			}
			t.Run(field+"/"+name, func(t *testing.T) {
				t.Parallel()
				srv := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc[field] = v })
				if p, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil); !errors.Is(err, oauth.ErrDiscovery) {
					t.Fatalf("%s=%q not refused as ErrDiscovery: %v (provider %+v)", field, v, err, p)
				}
			})
		}
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run("missing "+field, func(t *testing.T) {
			t.Parallel()
			srv := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc[field] = nil })
			if _, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil); !errors.Is(err, oauth.ErrDiscovery) {
				t.Fatalf("a document without %s was not refused as ErrDiscovery: %v", field, err)
			}
		})
	}
	t.Run("control: userinfo may be absent", func(t *testing.T) {
		srv := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc["userinfo_endpoint"] = nil })
		if _, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil); err != nil {
			t.Fatalf("a document without userinfo_endpoint was refused: %v", err)
		}
	})
	t.Run("control: the good document", func(t *testing.T) {
		srv := hostiletest.DiscoveryServer(t, nil)
		p, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil)
		if err != nil || p.Issuer != srv.URL || p.JWKSURL != srv.URL+"/jwks" {
			t.Fatalf("Discover = %+v, %v", p, err)
		}
	})
}

func TestHostile_Discovery_issuerArgumentThatMustBeRefusedBeforeAnyRequest(t *testing.T) {
	probe := &countingTransport{}
	hc := &http.Client{Transport: probe}
	for name, issuer := range map[string]string{
		"empty": "", "plain http to a real host": "http://idp.example", "ftp": "ftp://idp.example", "no host": "https:///x",
		"opaque": "https:idp.example", "scheme-relative": "//idp.example", "relative": "/idp", "file": "file:///etc/passwd",
		"control character": "https://idp.example/\n", "uppercase LOCALHOST (not the documented spelling)": "http://LOCALHOST:1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := oauth.Discover(hostiletest.Ctx(t), issuer, hc); !errors.Is(err, oauth.ErrDiscovery) {
				t.Fatalf("issuer %q not refused as ErrDiscovery: %v", issuer, err)
			}
		})
	}
	if n := probe.requests.Load(); n != 0 {
		t.Fatalf("an unacceptable issuer still produced %d outbound request(s)", n)
	}
}

// Mix-up: tokens and documents of one provider presented under the name of another.
func TestHostile_Discovery_mixUpBetweenProviders(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	t.Run("a document that claims the honest provider's issuer", func(t *testing.T) {
		attacker := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc["issuer"] = "https://accounts.google.com" })
		if _, err := oauth.Discover(hostiletest.Ctx(t), attacker.URL, nil); err == nil {
			t.Fatal("an attacker-hosted document passed itself off as another issuer")
		}
	})
	t.Run("a token minted by provider P1 replayed to the client of provider P2", func(t *testing.T) {
		// Same client id and the same kid everywhere: the worst case for confusion.
		p1 := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil))))
		p2 := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &b.PublicKey, nil))))
		c1 := hostiletest.OIDCClient(t, p1.URL, func(c *oauth.Config) { c.Provider.Issuer = "https://p1.example" })
		c2 := hostiletest.OIDCClient(t, p2.URL, func(c *oauth.Config) { c.Provider.Issuer = "https://p2.example" })
		tok := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": "https://p1.example"}))
		if _, err := hostiletest.Verify(t, c1, tok); err != nil {
			t.Fatalf("control: P1's own token refused by P1: %v", err)
		}
		got, err := hostiletest.Verify(t, c2, tok)
		hostiletest.MustRejectToken(t, got, err)
	})
	t.Run("P2 claims P1's issuer in a token signed by P2's key", func(t *testing.T) {
		p1 := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil))))
		c1 := hostiletest.OIDCClient(t, p1.URL, func(c *oauth.Config) { c.Provider.Issuer = "https://p1.example" })
		forged := hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": "https://p1.example"})}.String(t)
		got, err := hostiletest.Verify(t, c1, forged)
		hostiletest.MustRejectToken(t, got, err)
	})
	t.Run("a client built from attacker discovery refuses the honest provider's token", func(t *testing.T) {
		keys := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil))))
		attacker := hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc["jwks_uri"] = keys.URL })
		p, err := oauth.Discover(hostiletest.Ctx(t), attacker.URL, nil)
		if err != nil {
			t.Fatalf("control: discovery failed: %v", err)
		}
		c, err := oauth.New(hostiletest.SilentProvider{}, oauth.Config{ClientID: hostiletest.ClientID, RedirectURL: "https://app.example/cb", Provider: p})
		if err != nil {
			t.Fatal(err)
		}
		// Honest token: signed by the key the attacker's document points at, but for the honest issuer.
		got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
		hostiletest.MustRejectToken(t, got, err)
	})
}

// countingTransport counts requests and answers each with an error, so a
// refusal that happens too late shows up as a request instead of as network noise.
type countingTransport struct{ requests atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return nil, errors.New("no network in this test")
}

func errorsIsDiscovery(err error) bool {
	return err != nil && strings.Contains(err.Error(), oauth.ErrDiscovery.Error())
}
