package oauth_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestMicrosoftPreset(t *testing.T) {
	const tenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	p, err := oauth.Microsoft(tenant)
	if err != nil {
		t.Fatalf("Microsoft(%q): %v", tenant, err)
	}
	if !strings.Contains(p.Issuer, tenant) || !strings.Contains(p.AuthURL, "authorize") || p.JWKSURL == "" {
		t.Errorf("unexpected Microsoft preset: %+v", p)
	}
	// A non-GUID tenant (the previously accepted verified-domain form) is
	// refused with a message that names the requirement.
	if _, err := oauth.Microsoft("contoso.onmicrosoft.com"); err == nil {
		t.Error("Microsoft must refuse a non-GUID tenant id")
	} else if !strings.Contains(err.Error(), "GUID") {
		t.Errorf("refusal must name the GUID requirement, got %v", err)
	}
}

// TestGooglePreset_acceptsBothIssuerSpellings pins the Google preset's
// IssuerValidator: it must accept the https form and the bare host, and
// nothing else. A regression that drops one spelling fails the first pair; a
// regression that widens the set fails the third.
func TestGooglePreset_acceptsBothIssuerSpellings(t *testing.T) {
	p := oauth.Google()
	if p.IssuerValidator == nil {
		t.Fatal("Google preset must wire an IssuerValidator")
	}
	for _, iss := range []string{
		"https://accounts.google.com",
		"accounts.google.com",
	} {
		if !p.IssuerValidator(iss) {
			t.Errorf("Google preset must accept issuer %q", iss)
		}
	}
	for _, iss := range []string{
		"https://accounts.google.com/", // trailing slash
		"http://accounts.google.com",
		"accounts.google.com.evil.example",
		"https://evil.example",
	} {
		if p.IssuerValidator(iss) {
			t.Errorf("Google preset must reject issuer %q", iss)
		}
	}
}

// TestGooglePreset_acceptsTheBareHostIDToken exercises the end-to-end path:
// sign an ID token with iss="accounts.google.com", verify it against a
// provider configured via oauth.Google(), and check the verifier approves.
// Without the IssuerValidator on the preset, this would fail on the exact
// issuer match.
func TestGooglePreset_acceptsTheBareHostIDToken(t *testing.T) {
	key := oauthtest.MustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, oauthtest.KID, n, e)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	cfg := oauth.Google()
	cfg.AuthURL = srv.URL + "/a"
	cfg.TokenURL = srv.URL + "/token"
	cfg.JWKSURL = srv.URL
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider:    cfg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	signed := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims("accounts.google.com", "n"))
	if _, err := c.VerifyIDToken(context.Background(), signed, "n"); err != nil {
		t.Errorf("bare-host issuer must verify, got %v", err)
	}
}

// TestMicrosoftPreset_rejectsDomainWithGUIDMessage pins the preset's GUID
// requirement and the error message that names it. A caller who passes a
// domain has to learn from the error what the preset wants, so the message is
// part of the contract: a regression that removes the word "GUID" fails.
func TestMicrosoftPreset_rejectsDomainWithGUIDMessage(t *testing.T) {
	for _, tenant := range []string{
		"contoso.onmicrosoft.com",
		"common",
		"",
		"not-a-guid",
	} {
		_, err := oauth.Microsoft(tenant)
		if err == nil {
			t.Errorf("Microsoft(%q) must be refused", tenant)
			continue
		}
		if !strings.Contains(err.Error(), "GUID") {
			t.Errorf("Microsoft(%q) refusal must name the GUID requirement, got %v", tenant, err)
		}
	}
}
