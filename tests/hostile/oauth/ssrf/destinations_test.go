package ssrf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a provider whose discovery document, or whose DNS records, steer
// the client's server-side requests at addresses the operator never meant to
// reach. Effect they want: the token, JWKS and userinfo requests (the token
// request carries the code and the client secret) land on an internal service.

var internalURLs = []string{
	"http://127.0.0.1:9/admin", "http://localhost/admin", "http://[::1]/admin",
	"https://169.254.169.254/latest/meta-data/", "https://10.0.0.5/jwks", "https://192.168.1.1/",
	"https://[fd00::1]/", "https://127.0.0.1:9/x", "https://localhost/x",
	"https://100.100.100.200/", "https://0.0.0.0/", "https://[::ffff:10.0.0.5]/",
	"https://metadata.google.internal/computeMetadata/v1/",
}

func TestHostile_Discovery_endpointsMustNotPointInside(t *testing.T) {
	for _, v := range internalURLs {
		for _, field := range hostiletest.EndpointFields {
			t.Run(field+"="+v, func(t *testing.T) {
				hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(doc map[string]any) { doc[field] = v })
				p, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc)
				if err == nil {
					t.Fatalf("%s=%q was accepted: %+v", field, v, p)
				}
				if !errors.Is(err, oauth.ErrDiscovery) {
					t.Fatalf("refused, but not as ErrDiscovery: %v", err)
				}
			})
		}
	}
}

func TestHostile_Discovery_publicEndpointsStillWork(t *testing.T) {
	hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(doc map[string]any) { doc["token_endpoint"] = "https://login.example.net/token" })
	if _, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestHostile_Discovery_privateNetworkIsAnExplicitOptIn(t *testing.T) {
	hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(doc map[string]any) {
		doc["token_endpoint"] = "https://10.0.0.5/token"
		doc["jwks_uri"] = "https://192.168.1.1/jwks"
	})
	p, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc, oauth.AllowPrivateNetwork())
	if err != nil {
		t.Fatalf("opt-in: %v", err)
	}
	if p.TokenURL != "https://10.0.0.5/token" {
		t.Fatalf("token endpoint = %q", p.TokenURL)
	}
}

func TestHostile_Discovery_loopbackIssuerVouchesForLoopbackOnly(t *testing.T) {
	srv := hostiletest.DiscoveryServer(t, nil)
	if _, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil); err != nil {
		t.Fatalf("a loopback issuer with loopback endpoints: %v", err)
	}
	srv = hostiletest.DiscoveryServer(t, func(doc map[string]any, _ string) { doc["token_endpoint"] = "https://169.254.169.254/token" })
	if p, err := oauth.Discover(hostiletest.Ctx(t), srv.URL, nil); err == nil {
		t.Fatalf("a loopback issuer may not vouch for a metadata address: %+v", p)
	}
}

func manualConfig(mut func(p *oauth.Provider)) oauth.Config {
	cfg := oauth.Config{
		ClientID: hostiletest.ClientID, RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer: hostiletest.Issuer, AuthURL: "https://idp.example/auth",
			TokenURL: "https://idp.example/token", JWKSURL: "https://idp.example/jwks",
			UserInfoURL: "https://idp.example/userinfo",
		},
	}
	mut(&cfg.Provider)
	return cfg
}

func TestHostile_Config_internalEndpointsAreRefusedUnlessOptedIn(t *testing.T) {
	set := map[string]func(p *oauth.Provider, v string){
		"auth":     func(p *oauth.Provider, v string) { p.AuthURL = v },
		"token":    func(p *oauth.Provider, v string) { p.TokenURL = v },
		"jwks":     func(p *oauth.Provider, v string) { p.JWKSURL = v },
		"userinfo": func(p *oauth.Provider, v string) { p.UserInfoURL = v },
	}
	for _, v := range []string{
		"https://169.254.169.254/latest", "https://10.0.0.5/x", "https://192.168.1.1/x", "https://[fd00::1]/",
		"https://metadata.google.internal/x", "https://100.100.100.200/", "https://0.0.0.0/",
	} {
		for name, f := range set {
			cfg := manualConfig(func(p *oauth.Provider) { f(p, v) })
			if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Errorf("%s=%q: want ErrInvalidConfig, got %v", name, v, err)
			}
			cfg.AllowPrivateNetwork = true
			if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); err != nil {
				t.Errorf("%s=%q with AllowPrivateNetwork: %v", name, v, err)
			}
		}
	}
	// The documented development exception stays: a loopback endpoint the
	// developer typed is accepted.
	cfg := manualConfig(func(p *oauth.Provider) { p.TokenURL = "http://127.0.0.1:8080/token" })
	if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); err != nil {
		t.Errorf("loopback token endpoint: %v", err)
	}
}

// The host is a public name; the address it resolves to is not. The transport
// below models that answer by connecting to a local server whatever name it is
// asked for. The library must refuse the connection it is handed.
func TestHostile_Fetch_nameResolvingToLoopbackIsNotReached(t *testing.T) {
	internal, _ := hostiletest.ServeTLS(t, hostiletest.StaticBody(hostiletest.JWKSDoc()))
	target := internal.Listener.Addr().String()
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DialContext: func(c2 context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(c2, network, target)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- local test only.
	}
	t.Cleanup(tr.CloseIdleConnections)
	hc := &http.Client{Transport: tr}
	c := hostiletest.OIDCClient(t, "https://example.com/jwks", func(c *oauth.Config) { c.HTTPClient = hc })
	_, _ = c.VerifyIDToken(hostiletest.Ctx(t), hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
	if n := internal.Hits.Load(); n != 0 {
		t.Fatalf("the client sent %d request(s) to a name that resolves to loopback", n)
	}
	// The same transport is allowed through when the operator opts in.
	c = hostiletest.OIDCClient(t, "https://example.com/jwks", func(c *oauth.Config) { c.HTTPClient = hc; c.AllowPrivateNetwork = true })
	_, _ = c.VerifyIDToken(hostiletest.Ctx(t), hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
	if internal.Hits.Load() == 0 {
		t.Fatal("AllowPrivateNetwork did not lift the check")
	}
}

func TestHostile_Config_urlsCarryingCredentialsAreRefused(t *testing.T) {
	cfg := manualConfig(func(p *oauth.Provider) { p.TokenURL = "https://admin:hunter2@idp.example/token" })
	if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Errorf("token URL with credentials: %v", err)
	}
	cfg = manualConfig(func(p *oauth.Provider) { p.Issuer = "https://admin:hunter2@idp.example" })
	if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Errorf("issuer with credentials: %v", err)
	}
	cfg = manualConfig(func(*oauth.Provider) {})
	cfg.RedirectURL = "https://admin:hunter2@app.example/cb"
	if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Errorf("redirect URL with credentials: %v", err)
	}
}

func TestHostile_Discovery_urlsCarryingCredentialsAreRefused(t *testing.T) {
	for _, field := range hostiletest.EndpointFields {
		hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(doc map[string]any) { doc[field] = "https://admin:hunter2@jwks.example.net/keys" })
		if p, err := oauth.Discover(hostiletest.Ctx(t), hostiletest.RemoteIssuer, hc); err == nil {
			t.Errorf("%s with credentials was accepted: %+v", field, p)
		}
	}
	if _, err := oauth.Discover(hostiletest.Ctx(t), "https://admin:hunter2@idp.example.com", nil); err == nil {
		t.Error("an issuer with credentials was accepted")
	}
}
