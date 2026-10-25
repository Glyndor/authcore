package exchange_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// TestExchange_ClientSecretFunc_Success pairs the failure cases below: a
// func returning "s1" then "s2" must produce form fields carrying those
// exact values. The token server's request counter is the regression
// guard, and the empty Authorization header under client_secret_post is
// the secret-not-in-headers invariant.
const appleTestClientID = "com.example.services"

func TestExchange_ClientSecretFunc_Success(t *testing.T) {
	t.Parallel()
	var (
		got1  atomic.Value
		got2  atomic.Value
		calls atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header must be empty under client_secret_post, got %q", r.Header.Get("Authorization"))
		}
		switch calls.Load() {
		case 1:
			got1.Store(r.FormValue("client_secret"))
		case 2:
			got2.Store(r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	var which atomic.Int32
	secretFn := func(ctx context.Context) (string, error) {
		if which.Add(1) == 1 {
			return "s1", nil
		}
		return "s2", nil
	}
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:         appleTestClientID,
		ClientSecretFunc: secretFn,
		RedirectURL:      "https://app.example.com/auth/apple/callback",
		HTTPClient:       oauthtest.NewLoopbackClient(t, srv),
		Provider: oauth.Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, err := c.Exchange(context.Background(), "c", "v")
		if err != nil {
			t.Fatalf("Exchange #%d: %v", i+1, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("token endpoint saw %d requests, want 2", got)
	}
	if v := got1.Load(); v != "s1" {
		t.Errorf("first exchange client_secret = %v, want s1", v)
	}
	if v := got2.Load(); v != "s2" {
		t.Errorf("second exchange client_secret = %v, want s2", v)
	}
}

// TestExchange_ClientSecretFunc_Error pins that a func error short-circuits
// Exchange, wraps ErrExchange, and never reaches the token endpoint. The
// sErr sentinel is the regression guard: a future refactor that swallowed
// the inner error would lose it.
func TestExchange_ClientSecretFunc_Error(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	sErr := errors.New("secrets vault sealed")
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/cb",
		HTTPClient:  oauthtest.NewLoopbackClient(t, srv),
		ClientSecretFunc: func(ctx context.Context) (string, error) {
			return "", sErr
		},
		Provider: oauth.Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected Exchange to return an error when ClientSecretFunc fails")
	}
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("rejection must wrap ErrExchange, got %v", err)
	}
	if !errors.Is(err, sErr) {
		t.Fatalf("rejection must wrap the func's sentinel, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("token endpoint was called %d times, want 0 (the func error must short-circuit before the HTTP request)", calls.Load())
	}
}

// TestExchange_ClientSecretFunc_Empty pins that an empty string from the
// func is rejected before the request is built. Some token servers
// accept an empty client_secret as "no secret configured" and answer 401,
// which would mask the actual bug; the library catches it earlier.
func TestExchange_ClientSecretFunc_Empty(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/cb",
		HTTPClient:  oauthtest.NewLoopbackClient(t, srv),
		ClientSecretFunc: func(ctx context.Context) (string, error) {
			return "", nil
		},
		Provider: oauth.Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected an error when ClientSecretFunc returns empty")
	}
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("rejection must wrap ErrExchange, got %v", err)
	}
	if !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("rejection must name the empty-secret cause, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("token endpoint was called %d times, want 0", calls.Load())
	}
}
