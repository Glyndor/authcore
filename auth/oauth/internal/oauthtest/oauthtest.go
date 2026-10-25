// Package oauthtest holds the fixtures shared by the black-box tests of
// auth/oauth and of its internal sub-packages: a silent authcore.Provider,
// signing helpers and clients wired to an httptest server. It is imported by
// _test files only and never by product code.
package oauthtest

import (
	"net/http/httptest"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
)

// FakeProvider supplies the authcore.Provider that oauth.New asks for.
type FakeProvider struct{}

// Config returns the default authcore configuration.
func (FakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }

// Logger returns a logger that discards everything.
func (FakeProvider) Logger() authcore.Logger { return SilentLogger{} }

// Keys returns no key store.
func (FakeProvider) Keys() authcore.Keys { return nil }

// SilentLogger satisfies authcore.Logger with no output.
type SilentLogger struct{}

// Debug discards the message.
func (SilentLogger) Debug(string, ...any) {}

// Info discards the message.
func (SilentLogger) Info(string, ...any) {}

// Warn discards the message.
func (SilentLogger) Warn(string, ...any) {}

// Error discards the message.
func (SilentLogger) Error(string, ...any) {}

const (
	// ClientID is the client id every helper client is built with.
	ClientID = "client-123"
	// KID is the key id JWKSServer publishes its key under.
	KID = "test-key-1"
)

// NewClient builds a client whose Issuer/JWKS point at srv.
func NewClient(t *testing.T, srv *httptest.Server) *oauth.Client {
	t.Helper()
	return mustNew(t, oauth.Config{
		ClientID:    ClientID,
		RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{
			Issuer:   srv.URL,
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL,
		},
	})
}

// NewTokenClient builds an OIDC client with a single "openid" scope whose
// token endpoint is srv, so Exchange tests get past config validation.
func NewTokenClient(t *testing.T, srv *httptest.Server) *oauth.Client {
	t.Helper()
	return mustNew(t, oauth.Config{
		ClientID:    ClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"openid"},
		Provider: oauth.Provider{
			Issuer:   srv.URL,
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL,
		},
	})
}

// OAuth2Client builds a plain OAuth2 client (no OIDC) that reads the profile
// from userInfoURL.
func OAuth2Client(t *testing.T, userInfoURL string) *oauth.Client {
	t.Helper()
	return mustNew(t, oauth.Config{
		ClientID:    ClientID,
		RedirectURL: "https://app.example.com/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://provider.example/auth",
			TokenURL:    "https://provider.example/token",
			UserInfoURL: userInfoURL,
		},
	})
}

func mustNew(t *testing.T, cfg oauth.Config) *oauth.Client {
	t.Helper()
	c, err := oauth.New(FakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}
