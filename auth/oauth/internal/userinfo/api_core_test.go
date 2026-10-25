package userinfo_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestUserInfo_rejectsEmptyAccessToken(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()
	c := oauthtest.OAuth2Client(t, srv.URL)
	if _, err := c.UserInfo(context.Background(), ""); !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo on empty token, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("userinfo endpoint was hit %d times; an empty token must short-circuit", got)
	}
}

func TestUserInfo_rejectsNullBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()
	c := oauthtest.OAuth2Client(t, srv.URL)
	if _, err := c.UserInfo(context.Background(), "at"); !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo on null body, got %v", err)
	}
	// Acceptance pair: a real object returns the map.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"login":"octocat"}`))
	}))
	defer good.Close()
	got, err := oauthtest.OAuth2Client(t, good.URL).UserInfo(context.Background(), "at")
	if err != nil {
		t.Fatalf("acceptance: UserInfo, got %v", err)
	}
	if got["login"] != "octocat" {
		t.Fatalf("acceptance: login = %v", got["login"])
	}
}

func TestUserInfo_preservesLargeNumericID(t *testing.T) {
	// 9007199254740993 is 2^53 + 1; json.Unmarshal into map[string]any would
	// collapse it onto the same float64 as 2^53 (9007199254740992). With
	// UseNumber they decode as distinct json.Number values.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":9007199254740993,"near":9007199254740992}`))
	}))
	defer srv.Close()
	c := oauthtest.OAuth2Client(t, srv.URL)

	got, err := c.UserInfo(context.Background(), "at")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	idNum, ok := got["id"].(json.Number)
	if !ok {
		t.Fatalf("id must decode as json.Number, got %T", got["id"])
	}
	if got["id"] == got["near"] {
		t.Fatalf("large id collapsed onto neighbour: %v == %v", got["id"], got["near"])
	}
	if string(idNum) != "9007199254740993" {
		t.Fatalf("id = %q, want 9007199254740993", string(idNum))
	}
}
