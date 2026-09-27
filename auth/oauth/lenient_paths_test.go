package oauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Paths that accepted more than they should until 2026-09-25: a UserInfo 200
// that is not a profile, Basic credentials sent without the RFC 6749 form
// encoding, a caller's AuthMethods slice kept after New, and a second
// spelling of one ID token.

func userInfoClient(t *testing.T, body string) *oauth.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: testClientID, RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL + "/u"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestUserInfo_refusesAnErrorObjectAndAnEmptyProfile(t *testing.T) {
	for body, fragment := range map[string]string{
		`{"error":"invalid_token","error_description":"expired"}`: "provider returned an error object",
		`{}`: "provider returned an empty profile",
	} {
		info, err := userInfoClient(t, body).UserInfo(context.Background(), "at")
		if info != nil || !errors.Is(err, oauth.ErrUserInfo) || !strings.Contains(err.Error(), fragment) {
			t.Errorf("UserInfo(%s) = %v, %v; want ErrUserInfo naming %q", body, info, err, fragment)
		}
	}
	info, err := userInfoClient(t, `{"id":42,"login":"octocat"}`).UserInfo(context.Background(), "at")
	if err != nil || info["login"] != "octocat" {
		t.Fatalf("a real profile: %v, %v; want it returned", info, err)
	}
}

// basicTokenServer answers the token request and records the Basic
// credentials as an RFC 6749 server reads them: base64, then form-decoded.
func basicTokenServer(t *testing.T, gotID, gotSecret *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "no basic auth", http.StatusUnauthorized)
			return
		}
		var err error
		if *gotID, err = url.QueryUnescape(id); err != nil {
			t.Errorf("client id is not form-encoded: %v", err)
		}
		if *gotSecret, err = url.QueryUnescape(secret); err != nil {
			t.Errorf("client secret is not form-encoded: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func basicClient(t *testing.T, srv *httptest.Server, id, secret string, methods []string) *oauth.Client {
	t.Helper()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: id, ClientSecret: secret, RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{
			AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL + "/u",
			AuthMethods: methods,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExchange_formEncodesBasicCredentials(t *testing.T) {
	for _, tc := range []struct{ id, secret string }{
		{"my:client", "a+b%2Fc d"},    // every character that changes meaning
		{"client-123", "Ab3_x.y~Z-9"}, // the usual shape, which encoding leaves as is
	} {
		var gotID, gotSecret string
		srv := basicTokenServer(t, &gotID, &gotSecret)
		c := basicClient(t, srv, tc.id, tc.secret, []string{"client_secret_basic"})
		if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
			t.Fatalf("Exchange(%q): %v", tc.id, err)
		}
		if gotID != tc.id || gotSecret != tc.secret {
			t.Errorf("server read id %q secret %q, want %q %q", gotID, gotSecret, tc.id, tc.secret)
		}
	}
}

func TestNew_copiesTheAdvertisedAuthMethods(t *testing.T) {
	var gotID, gotSecret string
	srv := basicTokenServer(t, &gotID, &gotSecret)
	methods := []string{"client_secret_basic"}
	c := basicClient(t, srv, "client-123", "s3cret", methods)
	methods[0] = "private_key_jwt" // the caller reuses its slice after New

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange after the caller changed its slice: %v", err)
	}
	if gotSecret != "s3cret" {
		t.Fatalf("server read secret %q over Basic, want the configured one", gotSecret)
	}
}

// flipUnusedBit returns s with its last base64url character changed so that
// it decodes to the same bytes under the lenient decoder.
func flipUnusedBit(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[i^1])
}

func TestVerifyIDToken_refusesASecondSpellingOfTheToken(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)
	tok := signIDToken(t, key, testKID, validClaims(srv.URL, "n"))

	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("the token as signed: %v, want accepted", err)
	}
	for name, tc := range map[string]struct{ token, fragment string }{
		"line feed in the signature": {tok[:len(tok)-10] + "\n" + tok[len(tok)-10:], "outside the base64url alphabet"},
		"unused bits set":            {flipUnusedBit(t, tok), "illegal base64 data"},
	} {
		_, err := c.VerifyIDToken(context.Background(), tc.token, "n")
		if !errors.Is(err, oauth.ErrIDTokenInvalid) || !strings.Contains(err.Error(), tc.fragment) {
			t.Errorf("%s: %v, want ErrIDTokenInvalid naming %q", name, err, tc.fragment)
		}
	}
}
