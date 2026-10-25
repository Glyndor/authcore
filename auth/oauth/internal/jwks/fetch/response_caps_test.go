package fetch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestJWKSResponseCap pins the JWKS response-size guard at MaxBytes
// (1<<20). The cache is driven through Get directly. The accepted body
// at the cap is valid JWKS; the one byte over the cap is truncated at the
// limit reader, leaving JSON with an unterminated "pad" string, so the
// decoder fails with ErrJWKS.
//
// A cold-cache lookup refreshes the JWKS, and the refresh reads the body
// via io.LimitReader at MaxBytes. A cap+1 body is truncated mid-JSON,
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
		doc := paddedJWKSAt(MaxBytes, &key.PublicKey, kid)
		if len(doc) != MaxBytes {
			t.Fatalf("fixture drifted: doc is %d bytes, want %d", len(doc), MaxBytes)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(doc))
		}))
		defer srv.Close()

		set, err := Get(context.Background(), srv.Client(), srv.URL, errFetch, func() {})
		if err != nil {
			t.Fatalf("acceptance at cap: Get, got %v", err)
		}
		if len(set.Keys[kid]) != 1 {
			t.Fatalf("acceptance at cap: want the one key under %q, got %v", kid, set.Keys)
		}
	})

	t.Run("over cap", func(t *testing.T) {
		const kid = "k"
		key := mustGenRSA(t)
		doc := paddedJWKSOver(MaxBytes, &key.PublicKey, kid)
		if len(doc) != MaxBytes+1 {
			t.Fatalf("fixture drifted: doc is %d bytes, want %d", len(doc), MaxBytes+1)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(doc))
		}))
		defer srv.Close()

		_, err := Get(context.Background(), srv.Client(), srv.URL, errFetch, func() {})
		if !errors.Is(err, errFetch) {
			t.Fatalf("expected errFetch, got %v", err)
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

func mustGenRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return k
}
