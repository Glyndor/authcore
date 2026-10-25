package jwt_test

// Fixtures shared by the hostile JWT tests. Every test here goes through the
// public jwt API. A token the module did not issue is minted with golang-jwt
// and, where the attack needs it, the module's own signing key. That models an
// adversary who controls every byte of the token except the one thing they
// cannot make: a valid Ed25519 signature under a key the verifier trusts.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

const (
	subject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"
	jtiA    = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0002"
)

// extra is the application payload carried under the "extra" claim.
type extra struct {
	Role string `json:"role"`
}

// env is one authcore instance with its key material kept visible to the
// test, so the test can sign what the module would never sign.
type env struct {
	prov   authcore.Provider
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
	kid    string
}

func newEnv(t testing.TB) *env {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	prov, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatalf("authcore.New: %v", err)
	}
	e := &env{prov: prov, priv: priv, pub: pub, secret: secret}
	pair, err := e.module(t, jwt.Config{}).CreateTokens(subject, extra{})
	if err != nil {
		t.Fatalf("create tokens: %v", err)
	}
	e.kid, _ = decodeHeader(t, pair.AccessToken)["kid"].(string)
	if e.kid == "" {
		t.Fatal("issued token carries no kid")
	}
	return e
}

func (e *env) module(t testing.TB, cfg jwt.Config) *jwt.JWT[extra] {
	t.Helper()
	m, err := jwt.New[extra](e.prov, cfg)
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	return m
}

func decodeHeader(t testing.TB, token string) map[string]any {
	t.Helper()
	seg, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

// rebuildHeader swaps the header segment of token for the encoding of h and
// keeps payload and signature untouched.
func rebuildHeader(t testing.TB, token string, h map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	_, rest, _ := strings.Cut(token, ".")
	return base64.RawURLEncoding.EncodeToString(raw) + "." + rest
}

// claimsFor returns the claim set of a token this module accepts at this
// instant. A test overrides or deletes the field it attacks.
func claimsFor(typ string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":  jwt.DefaultConfig().Issuer,
		"aud":  jwt.DefaultConfig().Audience,
		"sub":  subject,
		"jti":  jtiA,
		"iat":  now.Add(-time.Second).Unix(),
		"exp":  now.Add(10 * time.Minute).Unix(),
		"type": typ,
	}
}

// with returns a copy of claims with key set to v, or deleted when v is nil.
func with(claims map[string]any, key string, v any) map[string]any {
	out := make(map[string]any, len(claims)+1)
	for k, val := range claims {
		out[k] = val
	}
	if v == nil {
		delete(out, key)
	} else {
		out[key] = v
	}
	return out
}

// sign mints a compact token with method and key. header entries are merged
// over the kid header, and a nil value deletes that header field.
func (e *env) sign(t testing.TB, method gjwt.SigningMethod, key any, header, claims map[string]any) string {
	t.Helper()
	tok := gjwt.NewWithClaims(method, gjwt.MapClaims(claims))
	tok.Header["kid"] = e.kid
	for k, v := range header {
		if v == nil {
			delete(tok.Header, k)
			continue
		}
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// signEdDSA signs with the module's real key.
func (e *env) signEdDSA(t testing.TB, header, claims map[string]any) string {
	t.Helper()
	return e.sign(t, gjwt.SigningMethodEdDSA, e.priv, header, claims)
}

// signRaw signs an exact payload string with the real key, for payloads that
// a map cannot express (duplicate keys, odd number spellings).
func (e *env) signRaw(t testing.TB, payload string) string {
	t.Helper()
	head := b64(`{"alg":"EdDSA","kid":"` + e.kid + `","typ":"JWT"}`)
	signingInput := head + "." + b64(payload)
	sig := ed25519.Sign(e.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func itoa(v any) string { return strconv.FormatInt(v.(int64), 10) }

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
