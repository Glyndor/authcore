package jwks_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestJWKS_refresh_status500(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	c := oauthtest.NewClient(t, bad)
	tok := oauthtest.SignIDToken(t, oauthtest.MustRSA(t), oauthtest.KID, oauthtest.ValidClaims(bad.URL, "n"))

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
	c := oauthtest.NewClient(t, garbage)
	tok := oauthtest.SignIDToken(t, oauthtest.MustRSA(t), oauthtest.KID, oauthtest.ValidClaims(garbage.URL, "n"))

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
	c := oauthtest.NewClient(t, hostile)
	tok := oauthtest.SignIDToken(t, oauthtest.MustRSA(t), oauthtest.KID, oauthtest.ValidClaims(hostile.URL, "n"))

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrJWKS) {
		t.Fatalf("expected ErrJWKS, got %v", err)
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("error does not name the cause (want read), got %v", err)
	}
}

func TestJWKS_concurrentUnknownKidsCollapse(t *testing.T) {
	key := oauthtest.MustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, oauthtest.KID, n, e)

	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	// A burst of tokens with distinct unknown kids must not fan out to one
	// outbound JWKS fetch each — singleflight + the throttle collapse them.
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := oauthtest.SignIDToken(t, key, fmt.Sprintf("bogus-%d", i), oauthtest.ValidClaims(srv.URL, "n"))
			_, _ = c.VerifyIDToken(context.Background(), tok, "n")
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&fetches); got > 3 {
		t.Errorf("burst of unknown kids caused %d JWKS fetches, want few", got)
	}
}

func TestVerifyIDToken_jwksNon200(t *testing.T) {
	key := oauthtest.MustRSA(t)
	// Return valid JWKS JSON at the failing status so the rejection must come
	// from the status check, not from decoding an empty body.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer bad.Close()
	c := oauthtest.NewClient(t, bad)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(bad.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected failure when JWKS endpoint returns 500")
	}
}

func TestVerifyIDToken_jwksEmpty(t *testing.T) {
	key := oauthtest.MustRSA(t)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer empty.Close()
	c := oauthtest.NewClient(t, empty)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(empty.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected failure when JWKS has no usable keys")
	}
}
