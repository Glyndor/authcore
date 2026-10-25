// Package issuer holds the issuer predicates of the provider presets (Google's two spellings, any
// Azure AD v2.0 tenant) and the Microsoft tenant id check.
package issuer

import "regexp"

// azureV2Issuer matches an Azure AD v2.0 issuer for any tenant:
// https://login.microsoftonline.com/<tenant-guid>/v2.0
var azureV2Issuer = regexp.MustCompile(`^https://login\.microsoftonline\.com/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/v2\.0$`)

// tenantGUID matches a Microsoft Entra tenant id. Real Azure AD ID
// tokens carry the tenant as a GUID, not a verified domain: the "iss" claim
// for a user in contoso.onmicrosoft.com is
// https://login.microsoftonline.com/<guid>/v2.0, never the bare domain. A
// preset built from the bare domain therefore pins an issuer no token will
// ever carry and rejects every login against that tenant.
var tenantGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AzureV2 reports whether iss is an Azure AD v2.0 issuer for any tenant.
func AzureV2(iss string) bool { return azureV2Issuer.MatchString(iss) }

// IsTenantGUID reports whether tenant is a Microsoft Entra tenant id GUID.
func IsTenantGUID(tenant string) bool { return tenantGUID.MatchString(tenant) }

// Google returns true for the two issuer spellings Google
// documents as valid in its ID tokens: the https form and the bare host.
// Anything else is refused. The function is part of Google's
// preset binding and is not a general purpose issuer matcher.
func Google(iss string) bool {
	return iss == "https://accounts.google.com" || iss == "accounts.google.com"
}
