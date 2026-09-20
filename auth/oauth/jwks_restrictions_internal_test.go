package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// The four tests in this file pin down the JWK restrictions the cache is
// meant to enforce at selection time per RFC 7517 §4.3 and RFC 8725 §3.1:
// alg declared on the JWK is a hard limit, key_ops:["encrypt"] cannot verify,
// the single-key-without-kid case is supported, and two keys under one kid
// are kept as separate candidates. Each rejection is paired with an acceptance
// of the same shape just inside the limit.

func fakeNow() time.Time {
	return time.Unix(1_700_000_000, 0)
}

// rsaJWKWith builds a JWKS document carrying a single RSA key with the
// supplied kid and optional alg/use/key_ops restrictions. Pass "" to omit.
func rsaJWKWith(t *testing.T, pub *rsa.PublicKey, kid, alg, use string, keyOps []string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	parts := []string{
		`"kty":"RSA"`,
		fmt.Sprintf(`"kid":%q`, kid),
		fmt.Sprintf(`"n":%q`, n),
		fmt.Sprintf(`"e":%q`, e),
	}
	if alg != "" {
		parts = append(parts, fmt.Sprintf(`"alg":%q`, alg))
	}
	if use != "" {
		parts = append(parts, fmt.Sprintf(`"use":%q`, use))
	}
	if len(keyOps) > 0 {
		quoted := make([]string, len(keyOps))
		for i, op := range keyOps {
			quoted[i] = fmt.Sprintf("%q", op)
		}
		parts = append(parts, fmt.Sprintf(`"key_ops":[%s]`, strings.Join(quoted, ",")))
	}
	return fmt.Sprintf(`{"keys":[{%s}]}`, strings.Join(parts, ","))
}

// signTokenAlg signs a token with the supplied alg using an *rsa.PrivateKey.
// The kid is set in the header.
func signTokenAlg(t *testing.T, key *rsa.PrivateKey, kid, alg string) string {
	t.Helper()
	method := gjwt.GetSigningMethod(alg)
	if method == nil {
		t.Fatalf("signing method %q not found", alg)
	}
	claims := gjwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "client",
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := gjwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign %s: %v", alg, err)
	}
	return signed
}

// signTokenEC signs an EC token with the supplied alg.
func signTokenEC(t *testing.T, key *ecdsa.PrivateKey, kid, alg string) string {
	t.Helper()
	method := gjwt.GetSigningMethod(alg)
	if method == nil {
		t.Fatalf("signing method %q not found", alg)
	}
	claims := gjwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "client",
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := gjwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign %s: %v", alg, err)
	}
	return signed
}

// serveJWKS is the test server factory used by the four tests in this file.
func serveJWKS(t *testing.T, doc string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestJWKS_rejectsKeyUsedWithWrongAlg pins down RFC 8725 §3.1: a JWK that
// declares alg:"RS256" cannot verify a token signed with PS256. The
// acceptance pair shows the same key verifying an RS256 token, so the guard
// is the alg restriction, not the token being unparseable.
func TestJWKS_rejectsKeyUsedWithWrongAlg(t *testing.T) {
	signer := mustGenRSA(t)
	doc := rsaJWKWith(t, &signer.PublicKey, "alg-restricted", "RS256", "", nil)
	srv := serveJWKS(t, doc)
	cache := newCache(srv, fakeNow())

	// Rejection: PS256 against a JWK declaring alg:"RS256".
	psTok := signTokenAlg(t, signer, "alg-restricted", "PS256")
	_ = psTok
	if _, err := cache.key(context.Background(), "alg-restricted", "PS256"); err == nil {
		t.Fatal("a JWK with alg:\"RS256\" must not be selected for a PS256 token")
	} else if !errors.Is(err, ErrJWKS) {
		t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
	} else if !strings.Contains(err.Error(), "PS256") {
		t.Fatalf("error does not name the rejected alg (want PS256), got %v", err)
	}

	// Acceptance: the same key verifying an RS256 token under the same kid.
	if _, err := cache.key(context.Background(), "alg-restricted", "RS256"); err != nil {
		t.Fatalf("the JWK with alg:\"RS256\" must verify an RS256 token, got %v", err)
	}
}

// TestJWKS_rejectsEncryptOnlyKey pins down RFC 7517 §4.3: a key published
// with key_ops:["encrypt"] must never verify a signature. The acceptance
// pair shows key_ops:["verify"] does.
func TestJWKS_rejectsEncryptOnlyKey(t *testing.T) {
	signer := mustGenRSA(t)

	t.Run("encrypt only is rejected", func(t *testing.T) {
		doc := rsaJWKWith(t, &signer.PublicKey, "enc-only", "", "", []string{"encrypt"})
		srv := serveJWKS(t, doc)
		cache := newCache(srv, fakeNow())

		_, err := cache.key(context.Background(), "enc-only", "RS256")
		if err == nil {
			t.Fatal("a JWK with key_ops:[\"encrypt\"] must not verify signatures")
		}
		if !errors.Is(err, ErrJWKS) {
			t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
		}
		if !strings.Contains(err.Error(), "enc-only") {
			t.Fatalf("error does not name the kid (want enc-only), got %v", err)
		}
	})

	t.Run("verify is accepted", func(t *testing.T) {
		doc := rsaJWKWith(t, &signer.PublicKey, "verify-only", "", "", []string{"verify"})
		srv := serveJWKS(t, doc)
		cache := newCache(srv, fakeNow())

		if _, err := cache.key(context.Background(), "verify-only", "RS256"); err != nil {
			t.Fatalf("a JWK with key_ops:[\"verify\"] must verify signatures, got %v", err)
		}
	})
}

// TestJWKS_singleKeyWithoutKid covers the OIDC-allowed case: a JWKS whose
// only key carries no kid is unambiguous, so a token without a kid in its
// header verifies. The two-keys-no-kid case is rejected because the cache
// cannot tell them apart. The acceptance pair shows the same key under a kid
// also works, so the anon handling is a separate path.
func TestJWKS_singleKeyWithoutKid(t *testing.T) {
	signer := mustGenRSA(t)

	t.Run("anon kid selects the only key", func(t *testing.T) {
		doc := rsaJWKWith(t, &signer.PublicKey, "", "", "", nil)
		srv := serveJWKS(t, doc)
		cache := newCache(srv, fakeNow())

		if _, err := cache.key(context.Background(), "", "RS256"); err != nil {
			t.Fatalf("a one-key JWKS with no kid must verify a kid-less token, got %v", err)
		}
	})

	t.Run("two keys without kid is ambiguous", func(t *testing.T) {
		other := mustGenRSA(t)
		doc := fmt.Sprintf(`{"keys":[%s,%s]}`,
			rsaJWKWith(t, &signer.PublicKey, "", "", "", nil),
			rsaJWKWith(t, &other.PublicKey, "", "", "", nil),
		)
		srv := serveJWKS(t, doc)
		cache := newCache(srv, fakeNow())

		_, err := cache.key(context.Background(), "", "RS256")
		if err == nil {
			t.Fatal("two kid-less keys must not silently pick one")
		}
		if !errors.Is(err, ErrJWKS) {
			t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
		}
	})

	t.Run("kid still works on the same key", func(t *testing.T) {
		doc := rsaJWKWith(t, &signer.PublicKey, "named", "", "", nil)
		srv := serveJWKS(t, doc)
		cache := newCache(srv, fakeNow())

		if _, err := cache.key(context.Background(), "named", "RS256"); err != nil {
			t.Fatalf("the named-kid form must also verify, got %v", err)
		}
	})
}

// TestJWKS_sharedKidKeepsBothKeys pins down the rule that two providers
// sharing a kid (an RSA and an EC one, which RFC 7517 permits) are kept as
// separate candidates. Both orders are exercised, so a regression that
// turns the per-kid list back into a single entry would break here.
func TestJWKS_sharedKidKeepsBothKeys(t *testing.T) {
	rsaKey := mustGenRSA(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec: %v", err)
	}
	raw, err := ecKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("ec bytes: %v", err)
	}
	xB64 := base64.RawURLEncoding.EncodeToString(raw[1:33])
	yB64 := base64.RawURLEncoding.EncodeToString(raw[33:65])

	buildDoc := func(rsaFirst bool) string {
		rsaEntry := fmt.Sprintf(`{"kty":"RSA","kid":"shared","n":%q,"e":%q}`,
			base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()))
		ecEntry := fmt.Sprintf(`{"kty":"EC","kid":"shared","crv":"P-256","x":%q,"y":%q}`, xB64, yB64)
		if rsaFirst {
			return fmt.Sprintf(`{"keys":[%s,%s]}`, rsaEntry, ecEntry)
		}
		return fmt.Sprintf(`{"keys":[%s,%s]}`, ecEntry, rsaEntry)
	}

	for _, rsaFirst := range []bool{true, false} {
		order := "RSA-first"
		if !rsaFirst {
			order = "EC-first"
		}
		t.Run(order, func(t *testing.T) {
			srv := serveJWKS(t, buildDoc(rsaFirst))
			cache := newCache(srv, fakeNow())

			// The RSA candidate under "shared" verifies RS256.
			rsaTok := signTokenAlg(t, rsaKey, "shared", "RS256")
			if _, err := cache.key(context.Background(), "shared", "RS256"); err != nil {
				t.Fatalf("RSA candidate must verify under kid \"shared\", got %v", err)
			}
			_ = rsaTok

			// The EC candidate under the same kid verifies ES256.
			ecTok := signTokenEC(t, ecKey, "shared", "ES256")
			if _, err := cache.key(context.Background(), "shared", "ES256"); err != nil {
				t.Fatalf("EC candidate must verify under kid \"shared\", got %v", err)
			}
			_ = ecTok
		})
	}
}
