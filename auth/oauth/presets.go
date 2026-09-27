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
// "iss" is always the signed-in user's own tenant GUID, never the alias.
// Accepting users from any tenant requires a hand-built Provider and the
// AzureMultiTenantIssuer validator; see the multi-tenant section of
// docs/oauth.md for the exact Config and the reason Discover cannot be
// used against the alias discovery document (it publishes the {tenantid}
// template issuer and refuses the round trip at the issuer-match check).
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

// Apple returns the Provider endpoints for Sign in with Apple.
//
// The authorization URL carries response_mode=form_post by design: requesting
// the "name" or "email" scopes requires it, and the callback arrives as an HTTP
// POST rather than a redirect. Read "code" and "state" from the request form
// just as you would for a query-string callback. Apple also posts a "user"
// field on the first authorization only, holding a JSON object with the
// user's name; it is not signed, has no identity meaning, and MUST NOT be
// treated as identity. Key accounts on the ID token's "sub" claim.
//
// Apple advertises only client_secret_post at its token endpoint: the client
// secret is a JWT signed with an ES256 key from the Apple Developer portal,
// passed in the form body. The Config struct accepts a static secret via
// ClientSecret, or a per-Exchange function via ClientSecretFunc. Use
// AppleClientSecret to obtain that function from your team's private key:
//
//	secret, err := oauth.AppleClientSecret(teamID, keyID, servicesID, p8PEM)
//	if err != nil { /* startup error */ }
//	mod, err := oauth.New(auth, oauth.Config{
//	    ClientID:         servicesID,
//	    ClientSecretFunc: secret,
//	    RedirectURL:      "https://app.example.com/auth/apple/callback",
//	    Provider:         oauth.Apple(),
//	})
//
// The key material in p8 stays on the server; never commit it.
func Apple() Provider {
	// response_mode=form_post is part of the documented Apple flow (Apple's
	// developer docs require it whenever the name or email scope is
	// requested) and must remain on the URL, so embedding it in the preset
	// instead of injecting it at AuthCodeURL time avoids the risk that a
	// caller passes a Config that drops it.
	// #nosec G101 -- these are Apple's public OIDC endpoint URLs, not credentials.
	return Provider{
		Issuer:        "https://appleid.apple.com",
		AuthURL:       "https://appleid.apple.com/auth/authorize?response_mode=form_post",
		TokenURL:      "https://appleid.apple.com/auth/token",
		JWKSURL:       "https://appleid.apple.com/auth/keys",
		AuthMethods:   []string{"client_secret_post"},
		DefaultScopes: []string{"openid", "email", "name"},
	}
}
