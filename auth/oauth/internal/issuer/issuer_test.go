package issuer

import "testing"

func TestAzureV2(t *testing.T) {
	t.Parallel()
	const guid = "9188040d-6c67-4c5b-b112-36a304b66dad"
	for iss, want := range map[string]bool{
		"https://login.microsoftonline.com/" + guid + "/v2.0":            true,
		"https://login.microsoftonline.com/common/v2.0":                  false,
		"https://login.microsoftonline.com/" + guid + "/v2.0/extra":      false,
		"http://login.microsoftonline.com/" + guid + "/v2.0":             false,
		"https://evil.example/https://login.microsoftonline.com/" + guid: false,
		"": false,
	} {
		if got := AzureV2(iss); got != want {
			t.Errorf("AzureV2(%q) = %v, want %v", iss, got, want)
		}
	}
}

func TestIsTenantGUID(t *testing.T) {
	t.Parallel()
	for tenant, want := range map[string]bool{
		"9188040d-6c67-4c5b-b112-36a304b66dad":  true,
		"9188040D-6C67-4C5B-B112-36A304B66DAD":  true,
		"contoso.onmicrosoft.com":               false,
		"common":                                false,
		"9188040d-6c67-4c5b-b112-36a304b66dad ": false,
		"":                                      false,
	} {
		if got := IsTenantGUID(tenant); got != want {
			t.Errorf("IsTenantGUID(%q) = %v, want %v", tenant, got, want)
		}
	}
}

func TestGoogleAcceptsOnlyTheTwoDocumentedSpellings(t *testing.T) {
	t.Parallel()
	for iss, want := range map[string]bool{
		"https://accounts.google.com":  true,
		"accounts.google.com":          true,
		"http://accounts.google.com":   false,
		"https://accounts.google.com/": false,
		"":                             false,
	} {
		if got := Google(iss); got != want {
			t.Errorf("Google(%q) = %v, want %v", iss, got, want)
		}
	}
}
