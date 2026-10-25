package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// ---- AuthCodeURL ------------------------------------------------------------

func TestAuthCodeURL_hasPKCEAndState(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: oauthtest.ClientID, RedirectURL: "https://app/cb", Provider: oauth.Google(),
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if req.State == "" || req.Nonce == "" || req.Verifier == "" {
		t.Fatal("state/nonce/verifier must be set")
	}
	u, _ := url.Parse(req.URL)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             oauthtest.ClientID,
		"code_challenge_method": "S256",
		"state":                 req.State,
		"nonce":                 req.Nonce,
	} {
		if q.Get(k) != want {
			t.Errorf("query %q = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q missing openid", q.Get("scope"))
	}
	if q.Get("code_challenge") == req.Verifier {
		t.Error("challenge must be the hash of the verifier, not the verifier itself")
	}
	// Acceptance pair: the challenge must equal base64url(sha256(verifier)),
	// not just differ from it. A regression that sends the verifier base64'd
	// again (or skips the hash) still differs and would pass a "differs" check
	// alone; pinning the expected value closes that hole.
	sum := sha256.Sum256([]byte(req.Verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if q.Get("code_challenge") != wantChallenge {
		t.Errorf("code_challenge = %q, want %q", q.Get("code_challenge"), wantChallenge)
	}
}

func TestAuthCodeURL_independentPerCall(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	a, _ := c.AuthCodeURL()
	b, _ := c.AuthCodeURL()
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier {
		t.Error("each AuthCodeURL must use fresh secrets")
	}
}

// ---- New validation ---------------------------------------------------------

// ---- VerifyIDToken (the security-critical path) -----------------------------

func TestVerifyIDToken_valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "nonce-xyz"))
	claims, err := c.VerifyIDToken(context.Background(), tok, "nonce-xyz")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "user-abc" {
		t.Errorf("Subject = %q, want user-abc", claims.Subject)
	}
	if claims.Email != "a@example.com" || !claims.EmailVerified {
		t.Errorf("email claims not parsed: %+v", claims)
	}
}

func TestVerifyIDToken_rejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	ctx := context.Background()

	t.Run("wrong nonce", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "right"))
		if _, err := c.VerifyIDToken(ctx, tok, "wrong"); err == nil {
			t.Error("expected rejection on nonce mismatch")
		}
	})
	t.Run("empty nonce supplied", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, ""))
		if _, err := c.VerifyIDToken(ctx, tok, ""); err == nil {
			t.Error("expected rejection when no nonce is supplied")
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		cl := oauthtest.ValidClaims("https://evil.example", "n")
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on issuer mismatch")
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["aud"] = "someone-else"
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on audience mismatch")
		}
	})
	t.Run("expired", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["exp"] = time.Now().Add(-time.Hour).Unix()
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on expired token")
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, other, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection when signed by an unlisted key")
		}
	})
	t.Run("hmac alg-confusion", func(t *testing.T) {
		// A token signed with HS256 must be refused (asymmetric algs only).
		hs := gjwt.NewWithClaims(gjwt.SigningMethodHS256, oauthtest.ValidClaims(srv.URL, "n"))
		hs.Header["kid"] = oauthtest.KID
		s, _ := hs.SignedString([]byte("secret"))
		if _, err := c.VerifyIDToken(ctx, s, "n"); err == nil {
			t.Error("expected rejection of an HS256 token")
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, "no-such-kid", oauthtest.ValidClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection for an unknown kid")
		}
	})
}

// ---- Exchange ---------------------------------------------------------------

func TestExchange_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code_verifier") == "" {
			t.Errorf("token request missing grant_type/code_verifier: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "id_token": "idt", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	tok, err := c.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at" || tok.IDToken != "idt" {
		t.Errorf("unexpected tokens: %+v", tok)
	}
}

func TestExchange_errors(t *testing.T) {
	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Return a valid JSON object so the rejection must come from the
			// status check, not from decoding an empty body. An empty body
			// would also fail decoding and pass the assertion for the wrong
			// reason.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad"}`))
		}))
		defer srv.Close()
		if _, err := oauthtest.NewClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrExchange on 400")
		}
	})
	t.Run("no id_token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"at"}`))
		}))
		defer srv.Close()
		if _, err := oauthtest.NewClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrNoIDToken")
		}
	})
}

func TestName(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	if c.Name() != "oauth" {
		t.Errorf("Name() = %q, want oauth", c.Name())
	}
}

func TestVerifyIDToken_rejectsNonOIDCProvider(t *testing.T) {
	// A plain-OAuth2 client (UserInfoURL only) has nothing to verify an ID
	// token against; VerifyIDToken must refuse the call rather than skip the
	// iss check silently.
	c := oauthtest.OAuth2Client(t, "https://provider.example/userinfo")
	_, err := c.VerifyIDToken(context.Background(), "anything", "nonce")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	// The sentinel alone does not pin this down: a malformed token, or a JWKS
	// that yields no key, reaches the same sentinel by another route. Require
	// the refusal to name the configuration, so removing the check is visible
	// here.
	if !strings.Contains(err.Error(), "not configured for OIDC") {
		t.Fatalf("error does not name the rule that refused the call: %v", err)
	}
}

func TestUserInfo_noURLConfigured(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	// An OIDC client has no UserInfoURL.
	_, err := oauthtest.NewClient(t, srv).UserInfo(context.Background(), "x")
	if !errors.Is(err, oauth.ErrNoUserInfo) {
		t.Fatalf("expected ErrNoUserInfo on an OIDC client, got %v", err)
	}
}

func TestAuthCodeURL_defaultScopesIncludeOpenID(t *testing.T) {
	// No scopes set -> the OIDC default set is used. The test pins the exact
	// decoded value so a regression that drops a scope or reorders them
	// (e.g. building a different "openid email profile" sequence) does not
	// pass on the "contains openid" check alone.
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google(),
	})
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got, want := u.Query().Get("scope"), "openid email profile"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestAuthCodeURL_callerScopesVerbatim(t *testing.T) {
	// Caller-supplied scopes are used as-is (no openid injected) — required for
	// plain-OAuth2 providers like GitHub.
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.GitHub(),
		Scopes: []string{"read:user", "user:email"},
	})
	req, _ := c.AuthCodeURL()
	if strings.Contains(req.URL, "openid") {
		t.Error("openid must not be injected into caller-supplied scopes")
	}
}

// TestAuthCodeURL_dedupsPreExistingQueryParameters pins the parse-then-Set
// path: when the AuthURL already carries a "state" or "code_challenge"
// parameter, the call must overwrite it instead of producing duplicates
// (which most OIDC servers read as the pre-existing value).
//
// The AuthURL below carries a pre-existing value for every parameter the
// library generates. Each one is asserted to be present exactly once, with
// the fresh value, so a regression that switched from url.Values.Set to
// url.Values.Add, or that left a parameter alone, would either repeat the
// pre-existing string ("plain", "pre", "evil.example", "token") or drop
// the fresh value.
func TestAuthCodeURL_dedupsPreExistingQueryParameters(t *testing.T) {
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: oauthtest.ClientID,
		Scopes:   []string{"openid email profile"},
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth?state=fixed&client_id=cid&code_challenge=pre-existing&code_challenge_method=plain&nonce=pre&redirect_uri=https://evil.example/cb&scope=pre&response_type=token",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
		RedirectURL: "https://app.example/cb",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse AuthCodeURL result: %v", err)
	}
	checks := map[string]string{
		"state":                 req.State,
		"nonce":                 req.Nonce,
		"client_id":             oauthtest.ClientID,
		"code_challenge":        "", // not equal to "pre-existing"; checked below
		"code_challenge_method": "S256",
		"redirect_uri":          "https://app.example/cb",
		"scope":                 "openid email profile",
		"response_type":         "code",
	}
	for key, want := range checks {
		vs := u.Query()[key]
		if len(vs) != 1 {
			t.Errorf("%s: got %d values (%v), want exactly 1", key, len(vs), vs)
			continue
		}
		if key == "code_challenge" {
			if vs[0] == "pre-existing" {
				t.Errorf("%s: must be overwritten, still %q", key, vs[0])
			}
			continue
		}
		if vs[0] != want {
			t.Errorf("%s = %q, want %q", key, vs[0], want)
		}
	}
}

// TestAuthCodeURL_handlesQuerylessAuthURL pins the parse path for a URL
// with no pre-existing query string.
func TestAuthCodeURL_handlesQuerylessAuthURL(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.HasPrefix(req.URL, "https://id.example/auth?") {
		t.Errorf("AuthCodeURL result = %q, want a path followed by ?", req.URL)
	}
}
