package urlcheck_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// A URL that is not parseable at all is refused before the scheme switch even
// runs; the parse-error branch is the only path still unexercised on
// requireHTTPS (existing tests already cover the https, http-loopback, and
// http-non-loopback cases).
func TestNew_rejectsUnparseableURL(t *testing.T) {
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://[invalid-ipv6", // url.Parse refuses the malformed host
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid URL") {
		t.Fatalf("error does not name the rule (want valid URL), got %v", err)
	}
	// Acceptance pair: a well-formed token URL passes through requireHTTPS.
	if _, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	}); err != nil {
		t.Fatalf("acceptance: well-formed config should pass, got %v", err)
	}
}

func TestNew_rejectsNonHTTPSEndpoint(t *testing.T) {
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "http://id.example/auth", // plaintext — must be rejected
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if err == nil {
		t.Error("expected a non-https endpoint to be rejected")
	}
}

func TestNew_allowsLoopbackHTTP(t *testing.T) {
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "http://localhost:8080/cb",
		Provider: oauth.Provider{
			AuthURL:     "http://127.0.0.1:9000/auth",
			TokenURL:    "http://127.0.0.1:9000/token",
			UserInfoURL: "http://127.0.0.1:9000/userinfo",
		},
	})
	if err != nil {
		t.Errorf("loopback http should be allowed for local dev, got %v", err)
	}
}

// TestNew_rejectsOpaqueHTTPSEndpoint requires the validation to refuse
// https:opaque and https:///path. Both passed validation before #444 and only
// failed later, when the fetch ran.
func TestNew_rejectsOpaqueHTTPSEndpoint(t *testing.T) {
	for name, raw := range map[string]string{
		"opaque":       "https:opaque",
		"empty host":   "https:///token",
		"opaque query": "https:?x=y",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
				ClientID:    "x",
				RedirectURL: "https://app.example/cb",
				Provider: oauth.Provider{
					Issuer:   "https://id.example",
					AuthURL:  "https://id.example/auth",
					TokenURL: raw,
					JWKSURL:  "https://id.example/jwks",
				},
			})
			if err == nil {
				t.Fatalf("URL %q must be rejected", raw)
			}
			if !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Fatalf("rejection must wrap ErrInvalidConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), "hierarchical") && !strings.Contains(err.Error(), "host") {
				t.Fatalf("rejection must name the rule (hierarchical/host), got %v", err)
			}
		})
	}
}

// TestNew_rejectsFragmentOnAuthURL pins the new fragment check. A fragment
// in the AuthURL would land every appended parameter inside the fragment,
// where no OIDC server reads them. Refuse it at validation.
func TestNew_rejectsFragmentOnAuthURL(t *testing.T) {
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:  "https://id.example/auth#frag",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
			Issuer:   "https://id.example",
		},
	})
	if err == nil {
		t.Fatal("an AuthURL with a fragment must be rejected")
	}
	if !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("rejection must name the fragment rule, got %v", err)
	}
}

// TestNew_acceptsFragmentFreeAuthURL is the acceptance pair for the
// fragment rule.
func TestNew_acceptsFragmentFreeAuthURL(t *testing.T) {
	if _, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
			Issuer:   "https://id.example",
		},
	}); err != nil {
		t.Fatalf("a fragment-free AuthURL must construct, got %v", err)
	}
}
