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

func userInfoClient(t *testing.T, body string) *oauth.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: oauthtest.ClientID, RedirectURL: "https://app.example.com/cb",
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
