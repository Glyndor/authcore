package userinfo_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// Six functions were below the 90% floor on a freshly-merged develop. Each
// test in this file exercises one rejection path that drove the floor down
// and pins the rejection down with errors.Is against the package sentinel
// plus a distinctive fragment of the message, so deleting a guard here is
// visible in the failure text rather than producing a string of "would
// still pass" greens.

// ---- jwks.refresh ----------------------------------------------------------

// ---- oauth.Exchange --------------------------------------------------------

// ---- oauth.UserInfo --------------------------------------------------------

func TestUserInfo_non2xxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := oauthtest.OAuth2Client(t, srv.URL)

	_, err := c.UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
	// Acceptance pair: a 200 with a real object returns the map.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer good.Close()
	if _, err := oauthtest.OAuth2Client(t, good.URL).UserInfo(context.Background(), "at"); err != nil {
		t.Fatalf("acceptance: UserInfo, got %v", err)
	}
}

func TestUserInfo_bodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("definitely not json"))
	}))
	defer srv.Close()
	c := oauthtest.OAuth2Client(t, srv.URL)

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
	c := oauthtest.OAuth2Client(t, srv.URL)

	_, err := c.UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("error does not name the cause (want trailing), got %v", err)
	}
}

// ---- idtoken claims --------------------------------------------------------

// ---- config.requireHTTPS ---------------------------------------------------

// ---- discovery.Discover ----------------------------------------------------

func TestUserInfo_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer the-access-token" {
			t.Errorf("missing/!wrong bearer: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"id":42,"login":"octocat"}`))
	}))
	defer srv.Close()

	info, err := oauthtest.OAuth2Client(t, srv.URL).UserInfo(context.Background(), "the-access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info["login"] != "octocat" {
		t.Errorf("login = %v, want octocat", info["login"])
	}
}

func TestUserInfo_non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return a valid JSON object so the rejection must come from the
		// status check, not from decoding an empty body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()
	if _, err := oauthtest.OAuth2Client(t, srv.URL).UserInfo(context.Background(), "x"); err == nil {
		t.Error("expected an error on a non-2xx userinfo response")
	}
}
