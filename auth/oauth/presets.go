package oauth

import (
	"fmt"
	"regexp"
)

// azureV2Issuer matches an Azure AD v2.0 issuer for any tenant:
// https://login.microsoftonline.com/<tenant-guid>/v2.0
var azureV2Issuer = regexp.MustCompile(`^https://login\.microsoftonline\.com/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/v2\.0$`)

// AzureMultiTenantIssuer returns an IssuerValidator that accepts any Azure AD
// v2.0 issuer, i.e. tokens from any tenant. Use it with the Microsoft "common"
// or "organizations" endpoints, where each user's token carries their own
// tenant id in "iss" and no fixed issuer string can match:
//
//	cfg := oauth.Config{
//	    ClientID: id, ClientSecret: secret, RedirectURL: cb,
//	    Provider:        oauth.Microsoft("common"),
//	    IssuerValidator: oauth.AzureMultiTenantIssuer(),
//	}
//
// This trusts users from EVERY Azure tenant. To restrict to specific tenants,
// also check the "tid" claim via IDClaims.Raw against your allowlist.
func AzureMultiTenantIssuer() func(issuer string) bool {
	return azureV2Issuer.MatchString
}

// Google returns the Provider endpoints for Google's OIDC service.
//
//	cfg := oauth.Config{
//	    ClientID:     id, ClientSecret: secret,
//	    RedirectURL:  "https://app.example.com/callback",
//	    Provider:     oauth.Google(),
//	}
func Google() Provider {
	// #nosec G101 -- these are Google's public OIDC endpoint URLs, not credentials.
	return Provider{
		Issuer:   "https://accounts.google.com",
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		JWKSURL:  "https://www.googleapis.com/oauth2/v3/certs",
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

// Discord returns the Provider endpoints for Discord's OAuth2 service. Like
// GitHub it is not OIDC; identity comes from UserInfo (the users/@me endpoint).
// Request scopes like "identify" and "email".
func Discord() Provider {
	// #nosec G101 -- these are Discord's public OAuth2 endpoint URLs, not credentials.
	return Provider{
		AuthURL:     "https://discord.com/oauth2/authorize",
		TokenURL:    "https://discord.com/api/oauth2/token",
		UserInfoURL: "https://discord.com/api/users/@me",
	}
}

// Microsoft returns the Provider endpoints for the Microsoft identity platform
// (Azure AD) for a SPECIFIC tenant id.
//
// Pass your concrete tenant id (a GUID, or a verified domain like
// "contoso.onmicrosoft.com"). Do NOT pass the multi-tenant aliases "common",
// "organizations", or "consumers": a real ID token's "iss" carries the
// signed-in user's own tenant GUID, never the alias, and VerifyIDToken enforces
// an exact issuer match — so an alias-based config rejects every token. To
// accept users from any tenant, pass Microsoft("common") and set
// Config.IssuerValidator to AzureMultiTenantIssuer() (which approves any Azure
// v2.0 per-tenant issuer); otherwise pin a single tenant here.
func Microsoft(tenant string) Provider {
	base := fmt.Sprintf("https://login.microsoftonline.com/%s", tenant)
	return Provider{
		Issuer:   fmt.Sprintf("%s/v2.0", base),
		AuthURL:  fmt.Sprintf("%s/oauth2/v2.0/authorize", base),
		TokenURL: fmt.Sprintf("%s/oauth2/v2.0/token", base),
		JWKSURL:  fmt.Sprintf("%s/discovery/v2.0/keys", base),
	}
}
