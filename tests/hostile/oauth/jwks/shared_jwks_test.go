package jwks_test

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a legitimate user of the provider, with a valid token minted for
// something else. Providers publish one key set for many applications and,
// for multi-tenant ones, many issuers, so a signature that verifies proves
// only that the provider signed it. Effect they want: a token issued to
// another application, or by another issuer, accepted as a login here.

func TestHostile_SharedJWKS_aTokenIsOnlyAcceptedByTheClientAndIssuerItNames(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	shared := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))) // one key set, three clients
	type app struct{ client, issuer string }
	apps := []app{
		{"client-123", "https://tenant-a.example"},
		{"client-456", "https://tenant-a.example"}, // another application of the same issuer
		{"client-123", "https://tenant-b.example"}, // the same application id under another issuer
	}
	clients := make([]*oauth.Client, len(apps))
	for i, ap := range apps {
		clients[i] = hostiletest.OIDCClient(t, shared.URL, func(c *oauth.Config) { c.ClientID, c.Provider.Issuer = ap.client, ap.issuer })
	}
	for ti, minted := range apps {
		tok := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, map[string]any{"aud": minted.client, "iss": minted.issuer}))
		for ci, ap := range apps {
			got, err := hostiletest.Verify(t, clients[ci], tok)
			if ti == ci {
				if err != nil {
					t.Errorf("control: the token minted for %+v was refused by its own client: %v", minted, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("the token minted for %+v was accepted by the client of %+v: %+v", minted, ap, got)
				continue
			}
			hostiletest.MustRejectToken(t, got, err)
		}
	}
}

// A multi-audience token, or one with an authorized party that is not us, is
// a token the provider issued for somebody else's session.
func TestHostile_SharedJWKS_tokensForAnotherApplicationAreRefusedWhateverTheirShape(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	c := hostiletest.OIDCClient(t, hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))).URL, nil)
	for name, over := range map[string]map[string]any{
		"we are one of two audiences":        {"aud": []string{hostiletest.ClientID, "other-app"}, "azp": hostiletest.ClientID},
		"we are one of two, azp is theirs":   {"aud": []string{hostiletest.ClientID, "other-app"}, "azp": "other-app"},
		"sole audience is us, azp is theirs": {"aud": hostiletest.ClientID, "azp": "other-app"},
		"audience is the issuer":             {"aud": hostiletest.Issuer},
		"audience is our redirect URL":       {"aud": "https://app.example/cb"},
		"audience is a prefix of our id":     {"aud": hostiletest.ClientID[:len(hostiletest.ClientID)-1]},
		"audience extends our id":            {"aud": hostiletest.ClientID + "-admin"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, over)))
			hostiletest.MustRejectToken(t, got, err)
		})
	}
}

// AzureMultiTenantIssuer is the one validator that approves a family of
// issuers. It must approve exactly the v2.0 issuer of a tenant GUID.
func TestHostile_SharedJWKS_theMultiTenantIssuerPatternMatchesOnlyTenantGUIDs(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	c := hostiletest.OIDCClient(t, hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))).URL, func(cfg *oauth.Config) {
		cfg.IssuerValidator = oauth.AzureMultiTenantIssuer()
	})
	const guid = "9188040d-6c67-4c5b-b112-36a304b66dad"
	issuerOf := func(tenant string) string { return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant) }
	accept := map[string]string{
		"a tenant":          issuerOf(guid),
		"upper-case digits": issuerOf("9188040D-6C67-4C5B-B112-36A304B66DAD"),
		"the all-zero id":   issuerOf("00000000-0000-0000-0000-000000000000"),
	}
	refuse := map[string]string{
		"the alias common":          issuerOf("common"),
		"the unexpanded template":   issuerOf("{tenantid}"),
		"a verified domain":         issuerOf("contoso.onmicrosoft.com"),
		"version 1 issuer":          "https://sts.windows.net/" + guid + "/",
		"trailing slash":            issuerOf(guid) + "/",
		"extra path before version": "https://login.microsoftonline.com/" + guid + "/x/v2.0",
		"extra path after":          issuerOf(guid) + "/extra",
		"query":                     issuerOf(guid) + "?tid=" + guid,
		"fragment":                  issuerOf(guid) + "#x",
		"plain http":                "http://login.microsoftonline.com/" + guid + "/v2.0",
		"upper-case scheme":         "HTTPS://login.microsoftonline.com/" + guid + "/v2.0",
		"upper-case host":           "https://LOGIN.microsoftonline.com/" + guid + "/v2.0",
		"another host":              "https://login.microsoftonline.com.evil.example/" + guid + "/v2.0",
		"another cloud":             "https://login.chinacloudapi.cn/" + guid + "/v2.0",
		"userinfo before the host":  "https://login.microsoftonline.com@evil.example/" + guid + "/v2.0",
		"braces around the id":      issuerOf("{" + guid + "}"),
		"one hex digit short":       issuerOf(guid[:len(guid)-1]),
		"one hex digit long":        issuerOf(guid + "0"),
		"non-hex letter":            issuerOf("9188040g-6c67-4c5b-b112-36a304b66dad"),
		"full-width digits":         issuerOf("９１８８０４０d-6c67-4c5b-b112-36a304b66dad"),
		"newline appended":          issuerOf(guid) + "\n",
		"nul appended":              issuerOf(guid) + "\x00",
		"leading space":             " " + issuerOf(guid),
		"two issuers joined":        issuerOf(guid) + " " + issuerOf(guid),
	}
	for name, iss := range accept {
		t.Run("accept "+name, func(t *testing.T) {
			if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": iss}))); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	for name, iss := range refuse {
		t.Run("refuse "+name, func(t *testing.T) {
			got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": iss})))
			hostiletest.MustRejectToken(t, got, err)
		})
	}
}
