package oauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// All four response-size guards in auth/oauth are constant 1<<20 (1 MiB),
// read from oauth.go (Exchange), jwks.go (JWKS refresh), discovery.go and
// userinfo.go on 2026-09-27. The cap value is asserted at the top of this
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

const responseCap = 1 << 20

// paddedBodyAt builds a JSON object of EXACTLY limit bytes, ending in `"}`,
// so the whole object is read by the limit reader: the closing quote and
// brace fit inside the cap.
func paddedBodyAt(limit int, prefix, suffix string) []byte {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("paddedBodyAt: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	inner := strings.Repeat("a", limit-len(prefix)-len(suffix))
	return []byte(prefix + inner + suffix)
}

// paddedBodyOver builds a JSON object of EXACTLY limit+1 bytes. The first
// limit bytes are identical to paddedBodyAt followed by one extra "a", so
// the cap cut at the limit reader stops one byte before the suffix, inside
// the "pad" string: the closing quote and brace are never read.
func paddedBodyOver(limit int, prefix, suffix string) []byte {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("paddedBodyOver: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	inner := strings.Repeat("a", limit-len(prefix)-len(suffix)+1)
	return []byte(prefix + inner + suffix)
}

// --- Exchange cap: oauth.go io.LimitReader(..., 1<<20) --------------------

func TestResponseCap_exchangeAtCap(t *testing.T) {
	body := paddedBodyAt(responseCap,
		`{"access_token":"at","token_type":"Bearer","id_token":"idt","pad":"`,
		`"}`)
	if len(body) != responseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	tok, err := c.Exchange(context.Background(), "c", "v")
	if err != nil {
		t.Fatalf("acceptance at cap: Exchange, got %v", err)
	}
	if tok.AccessToken != "at" {
		t.Fatalf("acceptance: AccessToken = %q, want at", tok.AccessToken)
	}
}

func TestResponseCap_exchangeOverCap(t *testing.T) {
	body := paddedBodyOver(responseCap,
		`{"access_token":"at","token_type":"Bearer","id_token":"idt","pad":"`,
		`"}`)
	if len(body) != responseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap+1)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
}

// --- Discover cap: discovery.go io.LimitReader(..., 1<<20) -----------------

func TestResponseCap_discoverAtCap(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(writeAtCap(srvURL, responseCap))
	}))
	srvURL = srv.URL
	defer srv.Close()

	body := writeAtCap(srvURL, responseCap)
	if len(body) != responseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap)
	}

	p, err := oauth.Discover(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("acceptance at cap: Discover, got %v", err)
	}
	if p.JWKSURL != srv.URL+"/jwks" {
		t.Fatalf("acceptance: JWKSURL = %q, want %q", p.JWKSURL, srv.URL+"/jwks")
	}
}

func TestResponseCap_discoverOverCap(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(writeOverCap(srvURL, responseCap))
	}))
	srvURL = srv.URL
	defer srv.Close()

	body := writeOverCap(srvURL, responseCap)
	if len(body) != responseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap+1)
	}

	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
}

// writeAtCap returns a discovery document body of EXACTLY limit bytes. The
// issuer and jwks_uri use the server's URL, so the test sets srvURL after
// httptest.NewServer returns and the handler closes over it.
func writeAtCap(srvURL string, limit int) []byte {
	prefix := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","jwks_uri":%q,"userinfo_endpoint":"https://id.example/userinfo","pad":"`, srvURL, srvURL+"/jwks")
	suffix := `"}`
	return paddedBodyAt(limit, prefix, suffix)
}

// writeOverCap returns a discovery document body of EXACTLY limit+1 bytes.
func writeOverCap(srvURL string, limit int) []byte {
	prefix := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","jwks_uri":%q,"userinfo_endpoint":"https://id.example/userinfo","pad":"`, srvURL, srvURL+"/jwks")
	suffix := `"}`
	return paddedBodyOver(limit, prefix, suffix)
}

// --- UserInfo cap: userinfo.go io.LimitReader(..., 1<<20) ------------------

func TestResponseCap_userInfoAtCap(t *testing.T) {
	body := paddedBodyAt(responseCap, `{"id":1,"login":"octocat","pad":"`, `"}`)
	if len(body) != responseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	if _, err := oauth2Client(t, srv.URL).UserInfo(context.Background(), "at"); err != nil {
		t.Fatalf("acceptance at cap: UserInfo, got %v", err)
	}
}

func TestResponseCap_userInfoOverCap(t *testing.T) {
	body := paddedBodyOver(responseCap, `{"id":1,"login":"octocat","pad":"`, `"}`)
	if len(body) != responseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), responseCap+1)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, err := oauth2Client(t, srv.URL).UserInfo(context.Background(), "at")
	if !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo, got %v", err)
	}
}
