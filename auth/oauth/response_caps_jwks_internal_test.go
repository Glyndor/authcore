package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestJWKSResponseCap pins the JWKS response-size guard at jwksMaxBytes
// (1<<20). The cache (newCache / jwks_trust_test.go) is driven directly, the
// way the existing JWKS restriction tests drive the cache. The accepted body
// at the cap is valid JWKS; the one byte over the cap is truncated at the
// limit reader, leaving JSON with an unterminated "pad" string, so the
// decoder fails with ErrJWKS.
//
// A cold-cache lookup refreshes the JWKS, and the refresh reads the body
// via io.LimitReader at jwksMaxBytes. A cap+1 body is truncated mid-JSON,
// the decoder fails, the cache records the failed attempt, and the lookup
// that triggered the refresh returns ErrJWKS (or ErrJWKSStale once past
// the TTL). A first call on a cold cache returns ErrJWKS, which is what the
// assertion below pins.
//
// Bodies are built in the TEST function (with len checks via t.Fatalf) and
// the handler only writes the prepared bytes. t.Fatalf is not called from
// the handler goroutine.
func TestJWKSResponseCap(t *testing.T) {
	t.Run("at cap", func(t *testing.T) {
		const kid = "k"
		key := mustGenRSA(t)
		doc := paddedJWKSAt(jwksMaxBytes, &key.PublicKey, kid)
		if len(doc) != jwksMaxBytes {
			t.Fatalf("fixture drifted: doc is %d bytes, want %d", len(doc), jwksMaxBytes)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(doc))
		}))
		defer srv.Close()

		cache := newCache(srv, time.Unix(1_700_000_000, 0))
		if _, err := cache.key(context.Background(), kid, "RS256"); err != nil {
			t.Fatalf("acceptance at cap: cache.key, got %v", err)
		}
	})

	t.Run("over cap", func(t *testing.T) {
		const kid = "k"
		key := mustGenRSA(t)
		doc := paddedJWKSOver(jwksMaxBytes, &key.PublicKey, kid)
		if len(doc) != jwksMaxBytes+1 {
			t.Fatalf("fixture drifted: doc is %d bytes, want %d", len(doc), jwksMaxBytes+1)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(doc))
		}))
		defer srv.Close()

		cache := newCache(srv, time.Unix(1_700_000_000, 0))
		_, err := cache.key(context.Background(), kid, "RS256")
		if !errors.Is(err, ErrJWKS) {
			t.Fatalf("expected ErrJWKS, got %v", err)
		}
	})
}

// paddedJWKSAt returns a JWKS document of EXACTLY limit bytes. limit and
// limit+1 together pin the size guard: at the limit, the whole object is
// read and the document parses cleanly; one byte over, the limit reader
// stops inside the "pad" string and the closing quote and brace are never
// read.
func paddedJWKSAt(limit int, pub *rsa.PublicKey, kid string) string {
	prefix, suffix := jwksPrefixSuffix(pub, kid)
	return paddedAt(limit, prefix, suffix)
}

// paddedJWKSOver returns a JWKS document of EXACTLY limit+1 bytes.
func paddedJWKSOver(limit int, pub *rsa.PublicKey, kid string) string {
	prefix, suffix := jwksPrefixSuffix(pub, kid)
	return paddedOver(limit, prefix, suffix)
}

func jwksPrefixSuffix(pub *rsa.PublicKey, kid string) (string, string) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	prefix := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q,"pad":"`, kid, n, e)
	suffix := `"}]}`
	return prefix, suffix
}

func paddedAt(limit int, prefix, suffix string) string {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("paddedAt: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	return prefix + strings.Repeat("a", limit-len(prefix)-len(suffix)) + suffix
}

func paddedOver(limit int, prefix, suffix string) string {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("paddedOver: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	return prefix + strings.Repeat("a", limit-len(prefix)-len(suffix)+1) + suffix
}
