package oauth_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// TestDocumentedMultiTenantProviderIsAccepted pins the multi-tenant Config
// published in docs/oauth.md against oauth.New, so a doc change that
// produces a builder error (e.g. an endpoint typo that the requireHTTPS
// check refuses) is visible here and not only in a maintainer's editor.
//
// New only validates config: it does not fetch, so the test is hermetic
// and quick.
func TestDocumentedMultiTenantProviderIsAccepted(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "client-id-from-env",
		RedirectURL: "https://app.example.com/auth/callback",
		Provider: oauth.Provider{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			JWKSURL:  "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		},
		IssuerValidator: oauth.AzureMultiTenantIssuer(),
	})
	if err != nil {
		t.Fatalf("documented multi-tenant Config must construct, got %v", err)
	}
}

// TestDocumentedFacebookProviderIsAccepted pins the hand-built Facebook
// Config published in docs/oauth.md against oauth.New, so a doc change
// that produces a builder error (an endpoint typo that the requireHTTPS
// check refuses, a missing JWKSURL that breaks isOIDC, or a fragment on
// the AuthURL) is visible here and not only in a maintainer's editor. The
// snippet in the doc pins Graph API v25.0; the test does the same. There
// is no secret literal: real Facebook secrets are per-app and must come
// from the deployment environment, never from a committed file.
//
// New only validates config: it does not fetch, so the test is hermetic
// and quick.
func TestDocumentedFacebookProviderIsAccepted(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "app-id-from-env",
		RedirectURL: "https://app.example.com/auth/facebook/callback",
		Provider: oauth.Provider{
			Issuer:   "https://www.facebook.com",
			AuthURL:  "https://www.facebook.com/v25.0/dialog/oauth",
			TokenURL: "https://graph.facebook.com/v25.0/oauth/access_token",
			JWKSURL:  "https://www.facebook.com/.well-known/oauth/openid/jwks/",
		},
	})
	if err != nil {
		t.Fatalf("documented Facebook Config must construct, got %v", err)
	}
}
