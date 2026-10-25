package exchange_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// All four response-size guards in auth/oauth are constant 1<<20 (1 MiB),
// read from internal/exchange (Exchange), internal/jwks (JWKS refresh), internal/discovery and
// internal/userinfo on 2026-09-27. The cap value is asserted at the top of this
// file and reused by every per-endpoint cap test, so a future tightening
// or loosening is a single edit.
//
// Each cap test follows the same shape: a VALID JSON body of exactly cap
// bytes returns nil (or the expected tokens), and a body padded with one
// additional byte is truncated mid-JSON-token by io.LimitReader, so the
// decoder fails with the endpoint's sentinel. The pad is constructed so the
// cap cut lands inside the unterminated "pad" string, leaving JSON whose
// first cap bytes are a complete object minus one closing quote. The decoder
// fails at parse time on the truncated body.
//
// Bodies are built in the TEST function (with len checks via t.Fatalf) and
// the handler only writes the prepared bytes. t.Fatalf is not called from
// the handler goroutine.

// --- Exchange cap: oauth.go io.LimitReader(..., 1<<20) --------------------

func TestResponseCap_exchangeAtCap(t *testing.T) {
	body := oauthtest.PaddedBodyAt(oauthtest.ResponseCap,
		`{"access_token":"at","token_type":"Bearer","id_token":"idt","pad":"`,
		`"}`)
	if len(body) != oauthtest.ResponseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := oauthtest.NewClient(t, srv)
	tok, err := c.Exchange(context.Background(), "c", "v")
	if err != nil {
		t.Fatalf("acceptance at cap: Exchange, got %v", err)
	}
	if tok.AccessToken != "at" {
		t.Fatalf("acceptance: AccessToken = %q, want at", tok.AccessToken)
	}
}

func TestResponseCap_exchangeOverCap(t *testing.T) {
	body := oauthtest.PaddedBodyOver(oauthtest.ResponseCap,
		`{"access_token":"at","token_type":"Bearer","id_token":"idt","pad":"`,
		`"}`)
	if len(body) != oauthtest.ResponseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap+1)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := oauthtest.NewClient(t, srv)
	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
}

// --- Discover cap: internal/discovery io.LimitReader(..., 1<<20) -----------------

// --- UserInfo cap: internal/userinfo io.LimitReader(..., 1<<20) ------------------
