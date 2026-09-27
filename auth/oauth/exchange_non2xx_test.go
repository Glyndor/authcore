package oauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// TestExchange_refusesNon2xxEvenWithSuccessBody pins the rule that the HTTP
// status check runs before the body decode. A 500 whose body looks like a
// token response must still be refused. The acceptance pair confirms the same
// body at 200 parses to a Tokens with the expected access token, so the body
// is well-formed: the only thing keeping the rejection out is the status.
func TestExchange_refusesNon2xxEvenWithSuccessBody(t *testing.T) {
	const body = `{"access_token":"at","token_type":"Bearer","id_token":"idt"}`

	t.Run("rejection", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()

		_, err := newClient(t, srv).Exchange(context.Background(), "c", "v")
		if !errors.Is(err, oauth.ErrExchange) {
			t.Fatalf("expected ErrExchange, got %v", err)
		}
		if !strings.Contains(err.Error(), "status 500") {
			t.Fatalf("refusal must name the status (want 500), got %v", err)
		}
	})

	t.Run("acceptance", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()

		got, err := newClient(t, srv).Exchange(context.Background(), "c", "v")
		if err != nil {
			t.Fatalf("acceptance: Exchange, got %v", err)
		}
		if got.AccessToken != "at" {
			t.Fatalf("acceptance: AccessToken = %q, want at", got.AccessToken)
		}
	})
}
