package oauth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Six functions were below the 90% floor on a freshly-merged develop. Each
// test in this file exercises one rejection path that drove the floor down
// and pins the rejection down with errors.Is against the package sentinel
// plus a distinctive fragment of the message, so deleting a guard here is
// visible in the failure text rather than producing a string of "would
// still pass" greens.

// ---- jwks.refresh ----------------------------------------------------------

func TestJWKS_refresh_status500(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	c := newClient(t, bad)
	tok := signIDToken(t, mustRSA(t), testKID, validClaims(bad.URL, "n"))

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrJWKS) {
		t.Fatalf("expected ErrJWKS, got %v", err)
	}
	// Three status paths in refresh share ErrJWKS: "status N", "decode: ...",
	// and "read: ...". The 500 response is the status path.
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("error does not name the cause (want status 500), got %v", err)
	}
}

func TestJWKS_refresh_bodyNotJSON(t *testing.T) {
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not a jwks document"))
	}))
	defer garbage.Close()
	c := newClient(t, garbage)
	tok := signIDToken(t, mustRSA(t), testKID, validClaims(garbage.URL, "n"))

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrJWKS) {
		t.Fatalf("expected ErrJWKS, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}

// A read mid-stream failure cannot be produced by LimitReader alone (it
// truncates cleanly without erroring), so the test server hijacks the
// connection: it advertises a 1024-byte body via Content-Length, sends 64
// bytes, and closes abruptly. The client's Read fails with an
// unexpected-EOF-class error and refresh surfaces the "read: %w" branch.
func TestJWKS_refresh_readFailure(t *testing.T) {
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("http server does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n"))
		_, _ = conn.Write(bytes.Repeat([]byte{'A'}, 64))
	}))
	defer hostile.Close()
	c := newClient(t, hostile)
	tok := signIDToken(t, mustRSA(t), testKID, validClaims(hostile.URL, "n"))

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrJWKS) {
		t.Fatalf("expected ErrJWKS, got %v", err)
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("error does not name the cause (want read), got %v", err)
	}
}

// ---- oauth.Exchange --------------------------------------------------------

// The token endpoint can return HTTP 200 with an OAuth error body. A long
// error_description is capped, and the truncation mark must survive into the
// surface error: the cap is the reason the cap exists.
func TestExchange_longErrorDescriptionIsTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 600 'x' characters: well past the 512-byte cap.
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"%s"}`, strings.Repeat("x", 600))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)

	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	// The truncated block plus the ellipsis marks: 512 'x' followed by "…".
	if !strings.Contains(err.Error(), strings.Repeat("x", 512)+"…") {
		t.Fatalf("error must surface the truncated description, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("error must include the provider error code, got %v", err)
	}
}

// A 200 response that is well-formed but missing token_type is a malformed
// success: the access token by itself tells the caller nothing about how to
// present it.
func TestExchange_emptyTokenTypeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":""}`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)

	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	// Acceptance pair: a body with token_type set parses and returns the tokens.
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer okSrv.Close()
	got, err := newOIDCClientWithTokenServer(t, okSrv).Exchange(context.Background(), "c", "v")
	if err != nil {
		t.Fatalf("acceptance: Exchange, got %v", err)
	}
	if got.TokenType != "Bearer" || got.AccessToken != "at" {
		t.Fatalf("acceptance: unexpected tokens %+v", got)
	}
}

// A 200 body that is not an object. The spec says the response is an object,
// so "null", "[…]", or a bare string is the endpoint speaking out of turn.
func TestExchange_nonObjectBodyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`"a bare json string"`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)

	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}

// ---- oauth.UserInfo --------------------------------------------------------

func TestUserInfo_non2xxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)

	_, err := c.UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
	// Acceptance pair: a 200 with a real object returns the map.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer good.Close()
	if _, err := oauth2Client(t, good.URL).UserInfo(context.Background(), "at"); err != nil {
		t.Fatalf("acceptance: UserInfo, got %v", err)
	}
}

func TestUserInfo_bodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("definitely not json"))
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)

	_, err := c.UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}

func TestUserInfo_trailingBytesRejected(t *testing.T) {
	// json.Decode reports trailing input as a separate error: {"id":1}garbage
	// is refused even though the leading object parses, because the response
	// is supposed to be exactly one JSON value.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1}garbage`))
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)

	_, err := c.UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("error does not name the cause (want trailing), got %v", err)
	}
}

// ---- idtoken claims --------------------------------------------------------

// An iat carried as a quoted string is a non-numeric NumericDate; RFC 7519
// requires a JSON number. The token must fail verification on that basis.
func TestVerifyIDToken_iatStringRejected(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	cl := validClaims(srv.URL, "n")
	cl["iat"] = "1700000000" // quoted: not a JSON number
	tok := signIDToken(t, key, testKID, cl)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "iat") {
		t.Fatalf("error does not name the rejected claim (want iat), got %v", err)
	}
}

// An aud carried as a JSON number has no string form to match the configured
// client id. A multi-tenant validator doesn't help: the only audience the
// caller ever trusts is the one it named as ClientID.
func TestVerifyIDToken_audNumberRejected(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	cl := validClaims(srv.URL, "n")
	cl["aud"] = 12345 // JSON number, not a string
	tok := signIDToken(t, key, testKID, cl)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Fatalf("error does not name the rejected claim (want aud), got %v", err)
	}
}

// ---- config.requireHTTPS ---------------------------------------------------

// A URL that is not parseable at all is refused before the scheme switch even
// runs; the parse-error branch is the only path still unexercised on
// requireHTTPS (existing tests already cover the https, http-loopback, and
// http-non-loopback cases).
func TestNew_rejectsUnparseableURL(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://[invalid-ipv6", // url.Parse refuses the malformed host
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid URL") {
		t.Fatalf("error does not name the rule (want valid URL), got %v", err)
	}
	// Acceptance pair: a well-formed token URL passes through requireHTTPS.
	if _, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	}); err != nil {
		t.Fatalf("acceptance: well-formed config should pass, got %v", err)
	}
}

// ---- discovery.Discover ----------------------------------------------------

func TestDiscover_non2xxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error does not name the status (want 502), got %v", err)
	}
	// Acceptance pair: a valid document on a separate server parses and returns
	// the provider. The closure captures goodURL so the discovery response can
	// echo its own URL back as the issuer.
	var goodURL string
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			goodURL, goodURL+"/a", goodURL+"/t", goodURL+"/j")
	}))
	goodURL = good.URL
	defer good.Close()
	if _, err := oauth.Discover(context.Background(), good.URL, nil); err != nil {
		t.Fatalf("acceptance: Discover, got %v", err)
	}
}

func TestDiscover_bodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>oops</body></html>`))
	}))
	defer srv.Close()
	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}
