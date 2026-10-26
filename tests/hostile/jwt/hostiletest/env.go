// Package hostiletest holds the fixtures shared by the hostile JWT tests,
// one package per attack class under tests/hostile/jwt. Every test here goes through the
// public jwt API. A token the module did not issue is minted with golang-jwt
// and, where the attack needs it, the module's own signing key. That models an
// adversary who controls every byte of the token except the one thing they
// cannot make: a valid Ed25519 signature under a key the verifier trusts.
package hostiletest

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

// Fixed identifiers every token minted here carries.
const (
	Subject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"
	JtiA    = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0002"
)

// Extra is the application payload carried under the "extra" claim.
type Extra struct {
	Role string `json:"role"`
}

// Env is one authcore instance with its key material kept visible to the
// test, so the test can sign what the module would never sign.
type Env struct {
	Prov   authcore.Provider
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	Secret []byte
	Kid    string
}

// NewEnv builds an Env with a fresh Ed25519 key pair and a provider holding it.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil) // a nil reader is crypto/rand, which does not fail
	secret := make([]byte, 32)
	_, _ = rand.Read(secret) // crypto/rand.Read never returns an error
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	prov, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatalf("authcore.New: %v", err)
	}
	e := &Env{Prov: prov, Priv: priv, Pub: pub, Secret: secret}
	pair, err := e.Module(t, jwt.Config{}).CreateTokens(Subject, Extra{})
	if err != nil {
		t.Fatalf("create tokens: %v", err)
	}
	e.Kid, _ = DecodeHeader(t, pair.AccessToken)["kid"].(string)
	if e.Kid == "" {
		t.Fatal("issued token carries no kid")
	}
	return e
}

// Module builds the jwt module of the Env with cfg.
func (e *Env) Module(t testing.TB, cfg jwt.Config) *jwt.JWT[Extra] {
	t.Helper()
	m, err := jwt.New[Extra](e.Prov, cfg)
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	return m
}

// DecodeHeader returns the decoded JOSE header of token.
func DecodeHeader(t testing.TB, token string) map[string]any {
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

// RebuildHeader swaps the header segment of token for the encoding of h and
// keeps payload and signature untouched.
func RebuildHeader(t testing.TB, token string, h map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	_, rest, _ := strings.Cut(token, ".")
	return base64.RawURLEncoding.EncodeToString(raw) + "." + rest
}

// ClaimsFor returns the claim set of a token this module accepts at this
// instant. A test overrides or deletes the field it attacks.
func ClaimsFor(typ string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":  jwt.DefaultConfig().Issuer,
		"aud":  jwt.DefaultConfig().Audience,
		"sub":  Subject,
		"jti":  JtiA,
		"iat":  now.Add(-time.Second).Unix(),
		"exp":  now.Add(10 * time.Minute).Unix(),
		"type": typ,
	}
}

// With returns a copy of claims with key set to v, or deleted when v is nil.
func With(claims map[string]any, key string, v any) map[string]any {
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

// Sign mints a compact token with method and key. header entries are merged
// over the kid header, and a nil value deletes that header field.
func (e *Env) Sign(t testing.TB, method gjwt.SigningMethod, key any, header, claims map[string]any) string {
	t.Helper()
	tok := gjwt.NewWithClaims(method, gjwt.MapClaims(claims))
	tok.Header["kid"] = e.Kid
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

// SignEdDSA signs with the module's real key.
func (e *Env) SignEdDSA(t testing.TB, header, claims map[string]any) string {
	t.Helper()
	return e.Sign(t, gjwt.SigningMethodEdDSA, e.Priv, header, claims)
}

// SignRaw signs an exact payload string with the real key, for payloads that
// a map cannot express (duplicate keys, odd number spellings).
func (e *Env) SignRaw(t testing.TB, payload string) string {
	t.Helper()
	head := B64(`{"alg":"EdDSA","kid":"` + e.Kid + `","typ":"JWT"}`)
	signingInput := head + "." + B64(payload)
	sig := ed25519.Sign(e.Priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Itoa formats an int64 held in an any as decimal.
func Itoa(v any) string { return strconv.FormatInt(v.(int64), 10) }

// B64 encodes s as unpadded base64url.
func B64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
