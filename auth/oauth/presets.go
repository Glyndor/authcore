package oauth

import "fmt"

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

// Microsoft returns the Provider endpoints for the Microsoft identity platform
// (Azure AD) for the given tenant. Use "common" for multi-tenant + personal
// accounts, "organizations" for any work/school account, or a specific tenant
// id. The issuer for the multi-tenant endpoints contains the tenant id of the
// signed-in user, so prefer a single-tenant id when you can pin the issuer.
func Microsoft(tenant string) Provider {
	base := fmt.Sprintf("https://login.microsoftonline.com/%s", tenant)
	return Provider{
		Issuer:   fmt.Sprintf("%s/v2.0", base),
		AuthURL:  fmt.Sprintf("%s/oauth2/v2.0/authorize", base),
		TokenURL: fmt.Sprintf("%s/oauth2/v2.0/token", base),
		JWKSURL:  fmt.Sprintf("%s/discovery/v2.0/keys", base),
	}
}
