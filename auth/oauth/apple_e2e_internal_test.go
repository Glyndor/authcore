package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// TestAppleClientSecret_EndToEndLoopback builds a token server that
// parses the Apple client secret as a JWT (verifying it with the test
// key's public half), and signs an ES256/RSA ID token whose
// email_verified is the STRING "true" (Apple sends strings). The test
// then runs twice: a happy path where claims match, and a wrong-sub path
// where the handler answers 400 invalid_client and Exchange surfaces
// ErrExchange.
func TestAppleClientSecret_EndToEndLoopback(t *testing.T) {
	t.Parallel()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	p256DER, err := x509.MarshalPKCS8PrivateKey(p256)
	if err != nil {
		t.Fatalf("marshal p256: %v", err)
	}
	p256PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p256DER})

	idKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	sign, err := AppleClientSecret(appleTestTeamID, appleTestKeyID, appleTestClientID, p256PEM)
	if err != nil {
		t.Fatalf("AppleClientSecret: %v", err)
	}

	var (
		seenSub    atomic.Value
		seenAud    atomic.Value
		seenIss    atomic.Value
		tokenCalls atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			// JWKS: Apple signs ID tokens with RS256, so the published
			// key is the test RSA key.
			n := base64.RawURLEncoding.EncodeToString(idKey.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})
			fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q,"alg":"RS256","use":"sig"}]}`, "apple-rsa-1", n, e)
		case r.Method == http.MethodPost:
			tokenCalls.Add(1)
			_ = r.ParseForm()
			secret := r.FormValue("client_secret")
			parsed, err := gjwt.Parse(secret, func(tok *gjwt.Token) (any, error) {
				return &p256.PublicKey, nil
			}, gjwt.WithValidMethods([]string{"ES256"}))
			if err != nil {
				http.Error(w, "secret rejected: "+err.Error(), http.StatusUnauthorized)
				return
			}
			if !parsed.Valid {
				http.Error(w, "secret invalid", http.StatusUnauthorized)
				return
			}
			mc, _ := parsed.Claims.(gjwt.MapClaims)
			iss, _ := mc["iss"].(string)
			sub, _ := mc["sub"].(string)
			seenIss.Store(iss)
			seenSub.Store(sub)
			seenAud.Store(mc["aud"])
			if sub != appleTestClientID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			idTok := gjwt.NewWithClaims(gjwt.SigningMethodRS256, gjwt.MapClaims{
				"iss":            "https://appleid.apple.com",
				"aud":            appleTestClientID,
				"sub":            "apple.user.001",
				"email":          "user@example.com",
				"email_verified": "true",
				"nonce":          "n-once",
				"exp":            time.Now().Add(time.Hour).Unix(),
				"iat":            time.Now().Unix(),
			})
			idTok.Header["kid"] = "apple-rsa-1"
			signed, err := idTok.SignedString(idKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, signed)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := New(appleFakeProvider{}, Config{
		ClientID:         appleTestClientID,
		ClientSecretFunc: sign,
		RedirectURL:      "https://app.example.com/auth/apple/callback",
		HTTPClient:       newLoopbackClient(t, srv),
		Provider: Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL + "/token",
			JWKSURL:     srv.URL,
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tokens, err := c.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.IDToken == "" {
		t.Fatal("Exchange returned no ID token")
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token endpoint saw %d calls, want 1", tokenCalls.Load())
	}
	if v, _ := seenIss.Load().(string); v != appleTestTeamID {
		t.Errorf("secret iss = %q, want %q", v, appleTestTeamID)
	}
	if v, _ := seenSub.Load().(string); v != appleTestClientID {
		t.Errorf("secret sub = %q, want %q", v, appleTestClientID)
	}
	if v, _ := seenAud.Load().(string); v != "https://appleid.apple.com" {
		t.Errorf("secret aud = %q, want %q", v, "https://appleid.apple.com")
	}

	claims, err := c.VerifyIDToken(context.Background(), tokens.IDToken, "n-once")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "apple.user.001" {
		t.Errorf("Subject = %q, want apple.user.001", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", claims.Email)
	}
	if !claims.EmailVerified {
		t.Errorf("EmailVerified = false, want true (Apple sends the string \"true\")")
	}

	// Wrong-sub pair: a second run where the handler sees a wrong sub
	// answers 400 invalid_client and Exchange returns ErrExchange. We
	// point the secret at a client id the handler rejects.
	badSign, err := AppleClientSecret(appleTestTeamID, appleTestKeyID, "other.client", p256PEM)
	if err != nil {
		t.Fatalf("AppleClientSecret (wrong sub): %v", err)
	}
	c2, err := New(appleFakeProvider{}, Config{
		ClientID:         appleTestClientID,
		RedirectURL:      "https://app.example.com/auth/apple/callback",
		HTTPClient:       newLoopbackClient(t, srv),
		ClientSecretFunc: badSign,
		Provider: Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL + "/token",
			JWKSURL:     srv.URL,
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New (wrong sub): %v", err)
	}
	if _, err := c2.Exchange(context.Background(), "the-code", "the-verifier"); err == nil {
		t.Fatal("Exchange must fail when the handler answers invalid_client")
	} else if !errors.Is(err, ErrExchange) {
		t.Fatalf("Exchange error must wrap ErrExchange, got %v", err)
	}
}
