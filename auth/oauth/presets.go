package oauth

import (
	"fmt"
	"regexp"
)

// azureV2Issuer matches an Azure AD v2.0 issuer for any tenant:
// https://login.microsoftonline.com/<tenant-guid>/v2.0
var azureV2Issuer = regexp.MustCompile(`^https://login\.microsoftonline\.com/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/v2\.0$`)

// microsoftTenantGUID matches a Microsoft Entra tenant id. Real Azure AD ID
// tokens carry the tenant as a GUID, not a verified domain: the "iss" claim
// for a user in contoso.onmicrosoft.com is
// https://login.microsoftonline.com/<guid>/v2.0, never the bare domain. A
// preset built from the bare domain therefore pins an issuer no token will
// ever carry and rejects every login against that tenant.
var microsoftTenantGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AzureMultiTenantIssuer returns an IssuerValidator that accepts any Azure AD
// v2.0 issuer, i.e. tokens from any tenant. Use it with the Microsoft "common"
// or "organizations" endpoints, where each user's token carries their own
// tenant id in "iss" and no single string can match:
//
//	tenantID := "9188040d-6c67-4c5b-b112-36a304b66dad"
//	p, err := oauth.Microsoft(tenantID)
//	cfg := oauth.Config{
//	    ClientID: id, ClientSecret: secret, RedirectURL: cb,
//	    Provider:        p,
//	    IssuerValidator: oauth.AzureMultiTenantIssuer(),
//	}
//
// This trusts users from EVERY Azure tenant. To restrict to specific tenants,
// also check the "tid" claim via IDClaims.Raw against your allowlist.
func AzureMultiTenantIssuer() func(issuer string) bool {
	return azureV2Issuer.MatchString
}

// googleIssuerAccepted returns true for the two issuer spellings Google
// documents as valid in its ID tokens: the https form and the bare host.
// Anything else is refused. The function is exported as part of Google's
// preset binding and is not a general purpose issuer matcher.
func googleIssuerAccepted(iss string) bool {
	return iss == "https://accounts.google.com" || iss == "accounts.google.com"
}

// Google returns the Provider endpoints for Google's OIDC service.
//
//	cfg := oauth.Config{
//	    ClientID:     id, ClientSecret: secret,
//	    RedirectURL:  "https://app.example.com/callback",
//	    Provider:     oauth.Google(),
//	}
//
// Google signs ID tokens with two issuer spellings, "https://accounts.google.com"
// and the bare host "accounts.google.com", and documents both as valid. The
// preset wires that pair into Config.IssuerValidator so the verifier accepts
// either. A token with any other issuer is refused; the rule is tight, so a
// regression that widens it is visible in the rejection text.
func Google() Provider {
	// #nosec G101 -- these are Google's public OIDC endpoint URLs, not credentials.
	return Provider{
		Issuer:          "https://accounts.google.com",
		AuthURL:         "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:        "https://oauth2.googleapis.com/token",
		JWKSURL:         "https://www.googleapis.com/oauth2/v3/certs",
		IssuerValidator: googleIssuerAccepted,
	}
}

// GitHub returns the Provider endpoints for GitHub's OAuth2 service. GitHub is
// not OIDC — it issues no ID token — so identity comes from UserInfo (the
// /user endpoint). Request scopes like "read:user" and "user:email".
func GitHub() Provider {
	// #nosec G101 -- these are GitHub's public OAuth2 endpoint URLs, not credentials.
	return Provider{
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
	}
}

// Discord returns the Provider endpoints for Discord's OAuth2 service. It uses
// the OAuth2 plus UserInfo path on purpose: identity comes from users/@me,
// which returns Discord's own user object. Request scopes like "identify" and
// "email".
//
// Discord also publishes an OIDC discovery document, captured in
// testdata/providers/discord-discovery.json, and Discover parses it. Use
// Discover with the issuer "https://discord.com" instead of this preset to
// receive ID tokens. That path has not been exercised against a live Discord
// login here.
func Discord() Provider {
	// #nosec G101 -- these are Discord's public OAuth2 endpoint URLs, not credentials.
	return Provider{
		AuthURL:     "https://discord.com/oauth2/authorize",
		TokenURL:    "https://discord.com/api/oauth2/token",
		UserInfoURL: "https://discord.com/api/users/@me",
	}
}

// Microsoft returns the Provider endpoints for the Microsoft identity platform
// (Azure AD) for a SPECIFIC tenant.
//
// The argument must be a tenant id expressed as a GUID. Azure AD stamps the
// GUID into the "iss" claim of every token it mints; passing a verified
// domain like "contoso.onmicrosoft.com" builds endpoints at that path but
// pins an issuer no token will ever carry, and VerifyIDToken refuses every
// login against that tenant on the exact issuer match.
//
// Multi-tenant aliases ("common", "organizations", "consumers") are tenant
// ids too, but they are placeholders rather than real tenants: a token's
// "iss" is always the signed-in user's own tenant GUID, never the alias. To
// accept users from any tenant, use Discover against the discovery document
// at the alias and set Config.IssuerValidator to AzureMultiTenantIssuer(),
// which approves any per-tenant issuer.
func Microsoft(tenant string) (Provider, error) {
	if !microsoftTenantGUID.MatchString(tenant) {
		return Provider{}, fmt.Errorf("oauth: Microsoft tenant must be a tenant id GUID, got %q", tenant)
	}
	base := fmt.Sprintf("https://login.microsoftonline.com/%s", tenant)
	return Provider{
		Issuer:   fmt.Sprintf("%s/v2.0", base),
		AuthURL:  fmt.Sprintf("%s/oauth2/v2.0/authorize", base),
		TokenURL: fmt.Sprintf("%s/oauth2/v2.0/token", base),
		JWKSURL:  fmt.Sprintf("%s/discovery/v2.0/keys", base),
	}, nil
}
