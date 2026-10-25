package issuer_test

import (
	"context"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestVerifyIDToken_issuerValidatorMultiTenant(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()

	tenantIss := "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
	mk := func(validator func(string) bool) *oauth.Client {
		c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
			ClientID:    oauthtest.ClientID,
			RedirectURL: "https://app.example/cb",
			Provider: oauth.Provider{
				AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/t", JWKSURL: srv.URL,
				// no fixed Issuer — the validator handles it
			},
			IssuerValidator: validator,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c
	}

	// A token whose dynamic per-tenant issuer the validator approves verifies,
	// even though no fixed Provider.Issuer matches it.
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(tenantIss, "n"))
	ok := mk(func(iss string) bool { return iss == tenantIss })
	if _, err := ok.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Errorf("validator-approved issuer should verify, got %v", err)
	}

	// A validator that rejects the issuer fails closed.
	reject := mk(func(string) bool { return false })
	if _, err := reject.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("validator-rejected issuer must be refused")
	}
}

func TestAzureMultiTenantIssuer(t *testing.T) {
	accept := oauth.AzureMultiTenantIssuer()
	good := "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
	if !accept(good) {
		t.Errorf("expected %q to be accepted", good)
	}
	for _, bad := range []string{
		"https://accounts.google.com",
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v1.0",
		"http://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
	} {
		if accept(bad) {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
