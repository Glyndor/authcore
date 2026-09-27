package oauth_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Two bindings of an ID token to this client that the suite did not pin
// before 2026-09-25: the "azp" claim (OIDC Core 3.1.3.7), which #426 dropped,
// and the JWK "issuer" member Microsoft publishes to scope each key to a
// tenant. Each refusal is paired with the same token shape that verifies.

const (
	consumerTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	otherTenant    = "11111111-2222-3333-4444-555555555555"
	thirdTenant    = "66666666-7777-8888-9999-000000000000"
)

func azureIssuer(tenant string) string {
	return "https://login.microsoftonline.com/" + tenant + "/v2.0"
}

// issuerJWKSServer serves one RSA key under testKID carrying the given JWK
// "issuer" member, the shape of Microsoft's common JWKS.
func issuerJWKSServer(t *testing.T, pub *rsa.PublicKey, keyIssuer string) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","kid":%q,"n":%q,"e":%q,"issuer":%q}]}`, testKID, n, e, keyIssuer)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// multiTenantClient is the documented Azure multi-tenant setup: a hand-built
// Provider with AzureMultiTenantIssuer as the issuer check.
func multiTenantClient(t *testing.T, srv *httptest.Server) *oauth.Client {
	t.Helper()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:        testClientID,
		RedirectURL:     "https://app.example.com/cb",
		Provider:        oauth.Provider{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", JWKSURL: srv.URL},
		IssuerValidator: oauth.AzureMultiTenantIssuer(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func tenantClaims(issTenant, tid string) gjwt.MapClaims {
	cl := validClaims(azureIssuer(issTenant), "n")
	if tid != "" {
		cl["tid"] = tid
	}
	return cl
}

func verify(t *testing.T, c *oauth.Client, key *rsa.PrivateKey, cl gjwt.MapClaims) (*oauth.IDClaims, error) {
	t.Helper()
	return c.VerifyIDToken(context.Background(), signIDToken(t, key, testKID, cl), "n")
}

func wantRefusal(t *testing.T, err error, fragment string) {
	t.Helper()
	if !errors.Is(err, oauth.ErrIDTokenInvalid) || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("got %v, want ErrIDTokenInvalid naming %q", err, fragment)
	}
}

func TestVerifyIDToken_refusesAnotherClientsAZP(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	cl := validClaims(srv.URL, "n")
	cl["azp"] = "some-other-client"
	_, err := verify(t, c, key, cl)
	wantRefusal(t, err, "azp does not match client id")

	cl["azp"] = testClientID
	if _, err := verify(t, c, key, cl); err != nil {
		t.Fatalf("azp equal to the client id: %v, want accepted", err)
	}
}

func TestVerifyIDToken_refusesATokenOutsideTheSigningKeysTenant(t *testing.T) {
	key := mustRSA(t)
	c := multiTenantClient(t, issuerJWKSServer(t, &key.PublicKey, azureIssuer(consumerTenant)))

	_, err := verify(t, c, key, tenantClaims(otherTenant, otherTenant))
	wantRefusal(t, err, "the signing key is restricted to")

	got, err := verify(t, c, key, tenantClaims(consumerTenant, consumerTenant))
	if err != nil {
		t.Fatalf("token from the key's own tenant: %v, want accepted", err)
	}
	if got.Issuer != azureIssuer(consumerTenant) {
		t.Fatalf("issuer %q, want %q", got.Issuer, azureIssuer(consumerTenant))
	}
}

func TestVerifyIDToken_templateKeyIssuerIsCompletedWithTID(t *testing.T) {
	key := mustRSA(t)
	c := multiTenantClient(t, issuerJWKSServer(t, &key.PublicKey, "https://login.microsoftonline.com/{tenantid}/v2.0"))

	if _, err := verify(t, c, key, tenantClaims(otherTenant, otherTenant)); err != nil {
		t.Fatalf("iss and tid naming the same tenant: %v, want accepted", err)
	}

	_, err := verify(t, c, key, tenantClaims(otherTenant, thirdTenant))
	wantRefusal(t, err, "the signing key is restricted to")

	_, err = verify(t, c, key, tenantClaims(otherTenant, ""))
	wantRefusal(t, err, "the token has no tid")
}

// A key without an "issuer" member, which is every Google and Discord key,
// is not restricted: the fixed issuer check alone applies.
func TestVerifyIDToken_keyWithoutIssuerIsUnrestricted(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	if _, err := verify(t, newClient(t, srv), key, validClaims(srv.URL, "n")); err != nil {
		t.Fatalf("key without issuer member: %v, want accepted", err)
	}
}
