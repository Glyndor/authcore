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
