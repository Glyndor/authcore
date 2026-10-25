package userinfo_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestResponseCap_userInfoAtCap(t *testing.T) {
	body := oauthtest.PaddedBodyAt(oauthtest.ResponseCap, `{"id":1,"login":"octocat","pad":"`, `"}`)
	if len(body) != oauthtest.ResponseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	if _, err := oauthtest.OAuth2Client(t, srv.URL).UserInfo(context.Background(), "at"); err != nil {
		t.Fatalf("acceptance at cap: UserInfo, got %v", err)
	}
}

func TestResponseCap_userInfoOverCap(t *testing.T) {
	body := oauthtest.PaddedBodyOver(oauthtest.ResponseCap, `{"id":1,"login":"octocat","pad":"`, `"}`)
	if len(body) != oauthtest.ResponseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap+1)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := oauthtest.OAuth2Client(t, srv.URL).UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
}
