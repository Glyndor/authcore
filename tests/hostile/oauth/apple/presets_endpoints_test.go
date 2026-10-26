package apple_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a change to the library itself, or to a value it ships. A preset
// is the one place where the library, not the caller, decides where a client
// secret and an authorization code are sent, so each endpoint is pinned to
// the host its provider documents. A typo, a downgrade to http, a loopback
// left behind from debugging or a look-alike host would all be a code and
// secret handed to the wrong party.

func presets(t *testing.T) map[string]oauth.Provider {
	t.Helper()
	ms, err := oauth.Microsoft("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]oauth.Provider{
		"Google": oauth.Google(), "GitHub": oauth.GitHub(), "Discord": oauth.Discord(),
		"Microsoft": ms, "Apple": oauth.Apple(), "Vercel": oauth.Vercel(),
	}
}

// wantHosts is the host of [issuer, auth, token, jwks, userinfo]; "" means the
// preset has no such endpoint.
var wantHosts = map[string][5]string{
	"Google":    {"accounts.google.com", "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com", ""},
	"GitHub":    {"", "github.com", "github.com", "", "api.github.com"},
	"Discord":   {"", "discord.com", "discord.com", "", "discord.com"},
	"Microsoft": {"login.microsoftonline.com", "login.microsoftonline.com", "login.microsoftonline.com", "login.microsoftonline.com", ""},
	"Apple":     {"appleid.apple.com", "appleid.apple.com", "appleid.apple.com", "appleid.apple.com", ""},
	"Vercel":    {"vercel.com", "vercel.com", "api.vercel.com", "vercel.com", ""},
}

func TestHostile_Presets_everyEndpointIsHTTPSOnItsDocumentedPublicHost(t *testing.T) {
	for name, p := range presets(t) {
		want, ok := wantHosts[name]
		if !ok {
			t.Fatalf("preset %s has no pinned hosts: add it to wantHosts", name)
		}
		endpoints := [5]string{p.Issuer, p.AuthURL, p.TokenURL, p.JWKSURL, p.UserInfoURL}
		for i, label := range []string{"issuer", "auth", "token", "jwks", "userinfo"} {
			raw := endpoints[i]
			if raw == "" {
				if want[i] != "" {
					t.Errorf("%s %s endpoint disappeared", name, label)
				}
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("%s %s: %v", name, label, err)
				continue
			}
			switch {
			case want[i] == "":
				t.Errorf("%s gained a %s endpoint (%s): pin it in wantHosts", name, label, raw)
			case u.Scheme != "https":
				t.Errorf("%s %s endpoint is %q, not https", name, label, u.Scheme)
			case u.Hostname() != want[i]:
				t.Errorf("%s %s endpoint host is %q, want %q", name, label, u.Hostname(), want[i])
			case u.Port() != "" || u.User != nil || u.Fragment != "" || u.Opaque != "":
				t.Errorf("%s %s endpoint carries a port, credentials or fragment: %s", name, label, raw)
			case !strings.Contains(u.Hostname(), ".") || strings.HasSuffix(u.Hostname(), ".local") || strings.HasSuffix(u.Hostname(), ".internal"):
				t.Errorf("%s %s endpoint host %q is not a public name", name, label, u.Hostname())
			}
			if a, err := netip.ParseAddr(u.Hostname()); err == nil {
				t.Errorf("%s %s endpoint is a bare address %s", name, label, a)
			}
		}
	}
}

// Every preset also passes the library's own destination policy, with no
// opt-in: the policy and the presets agree about what "public" means.
func TestHostile_Presets_everyPresetIsAcceptedWithoutAnyPrivateNetworkOptIn(t *testing.T) {
	for name, p := range presets(t) {
		_, err := oauth.New(hostiletest.SilentProvider{}, oauth.Config{ClientID: hostiletest.ClientID, RedirectURL: "https://app.example/cb", Provider: p})
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Presets are values: changing the copy one caller got must not change the next.
func TestHostile_Presets_aCallerCannotAlterWhatTheNextCallerGets(t *testing.T) {
	first := oauth.Apple()
	first.AuthMethods[0] = "client_secret_basic"
	first.DefaultScopes[0] = "admin"
	first.TokenURL = "https://evil.example/token"
	second := oauth.Apple()
	if second.AuthMethods[0] != "client_secret_post" || second.DefaultScopes[0] != "openid" || second.TokenURL != "https://appleid.apple.com/auth/token" {
		t.Fatalf("a mutation leaked between callers: %+v", second)
	}
}

// The Apple client secret names Apple as its audience whatever the arguments
// hold: there is no argument that chooses the audience, and an identifier
// that looks like JSON or a URL stays a string.
func TestHostile_Apple_theSecretCanNotBeSteeredToAnotherAudience(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, clientID := range map[string]string{
		"json breakout":        `x","aud":"https://evil.example","sub":"y`,
		"a url":                "https://evil.example",
		"a newline":            "a\nb",
		"unicode":              "com.example.é\u202e",
		"quotes and backslash": `a"b\c`,
		"long":                 strings.Repeat("c", 4096),
	} {
		t.Run(name, func(t *testing.T) {
			fn, err := oauth.AppleClientSecret(appleTeam, appleKeyID, clientID, p8PEM(t, key))
			if err != nil {
				return // refusing the identifier is as good
			}
			secret, err := fn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, claims := parseAppleSecret(t, secret, &key.PublicKey)
			if claims["aud"] != "https://appleid.apple.com" {
				t.Fatalf("aud = %v (%T)", claims["aud"], claims["aud"])
			}
			if claims["sub"] != clientID || claims["iss"] != appleTeam {
				t.Fatalf("the identity was reshaped: sub=%v iss=%v", claims["sub"], claims["iss"])
			}
			if len(claims) != 5 {
				t.Fatalf("claims = %v, want exactly iss, iat, exp, aud, sub", claims)
			}
		})
	}
}

// The key is read once. Overwriting the caller's buffer afterwards, or
// calling with a context that carries values, changes nothing about whose
// key signs or for whom.
func TestHostile_Apple_theSigningKeyIsFixedAtConstruction(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	buf := p8PEM(t, key)
	fn, err := oauth.AppleClientSecret(appleTeam, appleKeyID, appleClient, buf)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf, p8PEM(t, other)) // the caller reuses its buffer
	type ctxKey struct{}
	cx := context.WithValue(context.Background(), ctxKey{}, "aud=https://evil.example")
	secret, err := fn(cx)
	if err != nil {
		t.Fatal(err)
	}
	header, claims := parseAppleSecret(t, secret, &key.PublicKey) // fails unless the original key signed
	if header["kid"] != appleKeyID || claims["aud"] != "https://appleid.apple.com" {
		t.Fatalf("header=%v claims=%v", header, claims)
	}
}
