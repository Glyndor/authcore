package hostile_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: whoever controls the arguments of AppleClientSecret (a
// misconfigured deployment, a tampered secret store) or the issuer string a
// token carries. Effects they want: a client secret signed with a key or for
// an identity other than the configured one, key material in an error that
// ends up in logs, or a token accepted under a look-alike issuer.

const (
	appleTeam   = "ABCDE12345"
	appleKeyID  = "KEYID67890"
	appleClient = "com.example.services"
)

func p8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestHostile_Apple_argumentsAndKeysThatMustBeRefused(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	goodPEM := p8PEM(t, good)
	if _, err := oauth.AppleClientSecret(appleTeam, appleKeyID, appleClient, goodPEM); err != nil {
		t.Fatalf("control: the valid arguments were refused: %v", err)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsaKeys()
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(good)
	sec1, _ := x509.MarshalECPrivateKey(good)
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}})

	keys := map[string][]byte{
		"nil":                          nil,
		"empty":                        {},
		"whitespace only":              []byte(" \n\t "),
		"raw DER without PEM":          der,
		"text before the BEGIN line":   append([]byte("# my key\n"), body...),
		"garbage after the END line":   append(append([]byte(nil), body...), []byte("\nextra")...),
		"a second PEM block after":     append(append([]byte(nil), body...), body...),
		"PEM headers":                  withHeaders,
		"SEC1 EC PRIVATE KEY block":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"PUBLIC KEY block":             pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		"ENCRYPTED PRIVATE KEY block":  pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}),
		"RSA key in PKCS8":             p8PEM(t, rsaKey),
		"P-384 key in PKCS8":           p8PEM(t, p384),
		"P-521 key in PKCS8":           p8PEM(t, p521),
		"Ed25519 key in PKCS8":         p8PEM(t, edKey),
		"truncated PEM":                body[:len(body)/2],
		"BEGIN line only":              []byte("-----BEGIN PRIVATE KEY-----\n"),
		"valid armour, garbage inside": []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"valid armour, bad base64":     []byte("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"),
		"five megabytes of A":          []byte("-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 5<<20) + "\n-----END PRIVATE KEY-----\n"),
		"NUL inside the armour":        append([]byte("-----BEGIN PRIVATE KEY-----\n\x00"), body[28:]...),
	}
	for name, p8 := range keys {
		t.Run("p8/"+name, func(t *testing.T) {
			fn, err := oauth.AppleClientSecret(appleTeam, appleKeyID, appleClient, p8)
			if err == nil {
				t.Fatalf("accepted (func nil=%v)", fn == nil)
			}
			if !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Fatalf("refused, but not as ErrInvalidConfig: %v", err)
			}
			// No key material in the error: not a base64 line, not a run of the DER.
			b64Body := base64.StdEncoding.EncodeToString(der)
			for i := 0; i+24 <= len(b64Body); i += 8 {
				if strings.Contains(err.Error(), b64Body[i:i+24]) {
					t.Fatalf("the error echoes key material: %v", err)
				}
			}
		})
	}

	ids := map[string]struct{ team, key, client string }{
		"team 9 chars":               {"ABCDE1234", appleKeyID, appleClient},
		"team 11 chars":              {"ABCDE123456", appleKeyID, appleClient},
		"team lower-case":            {"abcde12345", appleKeyID, appleClient},
		"team with a dash":           {"ABCDE-1234", appleKeyID, appleClient},
		"team with a newline":        {"ABCDE1234\n", appleKeyID, appleClient},
		"team with a NUL":            {"ABCDE1234\x00", appleKeyID, appleClient},
		"team multi-byte digit":      {"ABCDE1234٣", appleKeyID, appleClient},
		"team empty":                 {"", appleKeyID, appleClient},
		"key id 9 chars":             {appleTeam, "KEYID6789", appleClient},
		"key id with a space":        {appleTeam, "KEYID 7890", appleClient},
		"key id lower-case":          {appleTeam, "keyid67890", appleClient},
		"key id empty":               {appleTeam, "", appleClient},
		"client id empty":            {appleTeam, appleKeyID, ""},
		"client id leading space":    {appleTeam, appleKeyID, " " + appleClient},
		"client id trailing space":   {appleTeam, appleKeyID, appleClient + " "},
		"client id trailing newline": {appleTeam, appleKeyID, appleClient + "\n"},
		"client id leading tab":      {appleTeam, appleKeyID, "\t" + appleClient},
		"client id only whitespace":  {appleTeam, appleKeyID, "  "},
	}
	for name, a := range ids {
		t.Run("id/"+name, func(t *testing.T) {
			if _, err := oauth.AppleClientSecret(a.team, a.key, a.client, goodPEM); !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}
}

// parseAppleSecret verifies the secret's ES256 signature with pub and returns header and claims.
func parseAppleSecret(t *testing.T, secret string, pub *ecdsa.PublicKey) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		t.Fatalf("secret has %d segments", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %d bytes, %v", len(sig), err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the secret's signature does not verify with the configured key")
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

func TestHostile_Apple_secretIsShortLivedBoundToOneIdentityAndSignedByTheConfiguredKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fn, err := oauth.AppleClientSecret(appleTeam, appleKeyID, appleClient, p8PEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-2 * time.Second).Unix()
	secret, err := fn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	header, claims := parseAppleSecret(t, secret, &key.PublicKey)
	if header["alg"] != "ES256" || header["kid"] != appleKeyID {
		t.Errorf("header = %v", header)
	}
	if claims["iss"] != appleTeam || claims["sub"] != appleClient || claims["aud"] != "https://appleid.apple.com" {
		t.Errorf("claims = %v", claims)
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if iat < before || iat > time.Now().Add(2*time.Second).Unix() {
		t.Errorf("iat %d is not now", iat)
	}
	if exp-iat != 300 {
		t.Errorf("lifetime = %ds, want 300: a leaked secret must die in minutes, not months", exp-iat)
	}

	t.Run("a done context signs nothing", func(t *testing.T) {
		c, cancel := context.WithCancel(context.Background())
		cancel()
		if s, err := fn(c); err == nil || s != "" {
			t.Fatalf("signed with a cancelled context: %q, %v", s, err)
		}
	})
	t.Run("concurrent signing is safe and every secret verifies", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := fn(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				parseAppleSecret(t, s, &key.PublicKey)
			}()
		}
		wg.Wait()
	})
}

// The Apple preset against a token endpoint that checks the secret the way Apple does.
func TestHostile_Apple_exchangeSendsTheSecretInTheBodyAndNeverReusesIt(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fn, err := oauth.AppleClientSecret(appleTeam, appleKeyID, appleClient, p8PEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var secrets []string
	var viaHeader bool
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		secrets = append(secrets, r.PostForm.Get("client_secret"))
		viaHeader = viaHeader || r.Header.Get("Authorization") != ""
		if r.PostForm.Get("client_id") != appleClient {
			http.Error(w, "client_id", 400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`))
	}))
	p := oauth.Apple()
	p.TokenURL = srv.URL
	c, err := oauth.New(silentProvider{}, oauth.Config{ClientID: appleClient, ClientSecretFunc: fn, RedirectURL: "https://app.example/cb", Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.Exchange(ctx(t), "code", "verifier"); err != nil {
			t.Fatalf("Exchange: %v", err)
		}
	}
	if viaHeader {
		t.Error("Apple advertises client_secret_post only, but the secret went in a header")
	}
	if len(secrets) != 2 || secrets[0] == "" {
		t.Fatalf("secrets on the wire: %q", secrets)
	}
	for _, s := range secrets {
		parseAppleSecret(t, s, &key.PublicKey)
	}
}

func TestHostile_Presets_microsoftTenantMustBeAGUID(t *testing.T) {
	const guid = "11111111-2222-3333-4444-555555555555"
	if p, err := oauth.Microsoft(guid); err != nil || p.Issuer != "https://login.microsoftonline.com/"+guid+"/v2.0" {
		t.Fatalf("control: %+v, %v", p, err)
	}
	for name, tenant := range map[string]string{
		"common": "common", "organizations": "organizations", "consumers": "consumers", "domain": "contoso.onmicrosoft.com",
		"parent traversal": "../evil", "embedded traversal": guid + "/../../evil", "slash suffix": guid + "/", "path suffix": guid + "/x",
		"query": guid + "?x=1", "fragment": guid + "#x", "trailing newline": guid + "\n", "trailing space": guid + " ", "leading space": " " + guid,
		"braces": "{" + guid + "}", "no dashes": strings.ReplaceAll(guid, "-", ""), "extra group": guid + "-0000",
		"non-hex": "gggggggg-2222-3333-4444-555555555555", "multi-byte digit": "1111111١-2222-3333-4444-555555555555",
		"empty": "", "userinfo decoy": "evil.example@" + guid, "huge": strings.Repeat("a", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			if p, err := oauth.Microsoft(tenant); err == nil {
				t.Fatalf("accepted: %+v", p)
			}
		})
	}
}

func TestHostile_Presets_googleAcceptsExactlyTwoIssuerSpellings(t *testing.T) {
	srv := serve(t, staticBody(stdJWKS(t)))
	client := func(t *testing.T) *oauth.Client {
		p := oauth.Google()
		p.JWKSURL = srv.URL
		c, err := oauth.New(silentProvider{}, oauth.Config{ClientID: testClient, RedirectURL: "https://app.example/cb", Provider: p})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, iss := range []string{"https://accounts.google.com", "accounts.google.com"} {
		if _, err := verify(t, client(t), signA(t, claims(testNonce, map[string]any{"iss": iss}))); err != nil {
			t.Errorf("control: %q refused: %v", iss, err)
		}
	}
	for name, iss := range map[string]string{
		"suffix domain": "accounts.google.com.evil.example", "prefix domain": "evilaccounts.google.com", "https suffix domain": "https://accounts.google.com.evil.example",
		"trailing slash": "https://accounts.google.com/", "http": "http://accounts.google.com", "explicit port": "https://accounts.google.com:443",
		"upper case": "ACCOUNTS.GOOGLE.COM", "trailing dot": "https://accounts.google.com.", "trailing newline": "https://accounts.google.com\n",
		"leading space": " accounts.google.com", "parent domain": "google.com", "userinfo decoy": "https://accounts.google.com@evil.example",
		"other google host": "https://accounts.youtube.com", "empty": "",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := verify(t, client(t), signA(t, claims(testNonce, map[string]any{"iss": iss})))
			mustRejectToken(t, got, err)
		})
	}
}
