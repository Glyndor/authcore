// Package hostile_test attacks the OIDC/OAuth2 client of auth/oauth through
// its public API only. Every test assumes a concrete adversary (a hostile
// provider, a man in the middle, a user who controls a URL or a parameter, a
// compromised provider response) and tries to obtain an effect the library
// must refuse. All servers are local httptest servers: nothing leaves the
// machine, nothing sleeps for long, and every attack is deterministic.
package hostile_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
)

const (
	testClient = "client-123"
	testIssuer = "https://idp.example"
	testKID    = "k1"
	testNonce  = "nonce-abc"
)

// silentProvider supplies the authcore.Provider that oauth.New asks for.
type silentProvider struct{ log authcore.Logger }

func (silentProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (p silentProvider) Logger() authcore.Logger {
	if p.log != nil {
		return p.log
	}
	return discardLogger{}
}
func (silentProvider) Keys() authcore.Keys { return nil }

// discardLogger drops everything.
type discardLogger struct{}

func (discardLogger) Debug(string, ...any) {}
func (discardLogger) Info(string, ...any)  {}
func (discardLogger) Warn(string, ...any)  {}
func (discardLogger) Error(string, ...any) {}

// Keys are generated once: RSA generation dominates the cost of a test.
var (
	keyOnce sync.Once
	keyA    *rsa.PrivateKey // the provider's signing key
	keyB    *rsa.PrivateKey // some other issuer's key
)

func rsaKeys() (*rsa.PrivateKey, *rsa.PrivateKey) {
	keyOnce.Do(func() {
		var err error
		if keyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if keyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return keyA, keyB
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64Int(n *big.Int) string { return b64(n.Bytes()) }

// rsaJWK returns the JWK of pub with extra members merged in.
func rsaJWK(kid string, pub *rsa.PublicKey, extra map[string]any) map[string]any {
	k := map[string]any{
		"kty": "RSA", "n": b64Int(pub.N), "e": b64Int(big.NewInt(int64(pub.E))),
	}
	if kid != "" {
		k["kid"] = kid
	}
	for name, v := range extra {
		k[name] = v
	}
	return k
}

// ecJWK returns the JWK of pub with extra members merged in.
func ecJWK(kid, crv string, pub *ecdsa.PublicKey, extra map[string]any) map[string]any {
	size := (pub.Curve.Params().BitSize + 7) / 8
	point, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	k := map[string]any{
		"kty": "EC", "crv": crv,
		"x": b64(point[1 : 1+size]),
		"y": b64(point[1+size:]),
	}
	if kid != "" {
		k["kid"] = kid
	}
	for name, v := range extra {
		k[name] = v
	}
	return k
}

func jwksDoc(keys ...map[string]any) []byte {
	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	return out
}

// mint describes one hand-built compact JWS. Building the token by hand is the
// point: an attacker is not bound by what a JWT library is willing to emit.
type mint struct {
	Alg    string // "RS256" when empty; also PS*, ES*, HS*, and the spellings of "none"
	Key    *rsa.PrivateKey
	EC     *ecdsa.PrivateKey
	HMAC   []byte
	Header map[string]any // merged over {alg, typ, kid}; a nil value deletes the member
	Claims map[string]any
	// Kid is the "kid" header: testKID when empty, omitted when "-".
	Kid string
}

func (m mint) String(t *testing.T) string {
	t.Helper()
	alg := m.Alg
	if alg == "" {
		alg = "RS256"
	}
	header := map[string]any{"alg": alg, "typ": "JWT"}
	switch m.Kid {
	case "":
		header["kid"] = testKID
	case "-":
	default:
		header["kid"] = m.Kid
	}
	for name, v := range m.Header {
		if v == nil {
			delete(header, name)
			continue
		}
		header[name] = v
	}
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	c, err := json.Marshal(m.Claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := b64(h) + "." + b64(c)
	return input + "." + b64(m.sign(t, alg, []byte(input)))
}

func (m mint) sign(t *testing.T, alg string, input []byte) []byte {
	t.Helper()
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		h := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
		d := digest(h, input)
		var sig []byte
		var err error
		if alg[0] == 'R' {
			sig, err = rsa.SignPKCS1v15(rand.Reader, m.Key, h, d)
		} else {
			sig, err = rsa.SignPSS(rand.Reader, m.Key, h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		if err != nil {
			t.Fatalf("sign %s: %v", alg, err)
		}
		return sig
	case "ES256", "ES384", "ES512":
		h := map[string]crypto.Hash{"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512}[alg]
		r, s, err := ecdsa.Sign(rand.Reader, m.EC, digest(h, input))
		if err != nil {
			t.Fatalf("sign %s: %v", alg, err)
		}
		size := (m.EC.Curve.Params().BitSize + 7) / 8
		return append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case "HS256", "HS384", "HS512":
		newHash := map[string]func() hash.Hash{"HS256": sha256.New, "HS384": sha512.New384, "HS512": sha512.New}[alg]
		mac := hmac.New(newHash, m.HMAC)
		mac.Write(input)
		return mac.Sum(nil)
	case "none", "None", "NONE", "nOnE":
		return nil
	}
	t.Fatalf("mint: unsupported alg %q", alg)
	return nil
}

func digest(h crypto.Hash, in []byte) []byte {
	hh := h.New()
	hh.Write(in)
	return hh.Sum(nil)
}

// claims returns a claim set the verifier accepts, with overrides merged in.
// A nil override deletes the claim.
func claims(nonce string, over map[string]any) map[string]any {
	c := map[string]any{
		"iss": testIssuer, "aud": testClient, "sub": "user-abc",
		"email": "a@example.com", "email_verified": true, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	for name, v := range over {
		if v == nil {
			delete(c, name)
			continue
		}
		c[name] = v
	}
	return c
}

// idp is a local provider endpoint that counts the requests it receives.
type idp struct {
	*httptest.Server
	hits atomic.Int64
}

// serve starts a plain-HTTP loopback server (the one plaintext exception the
// library allows) whose handler is wrapped by a request counter.
func serve(t *testing.T, h http.Handler) *idp {
	t.Helper()
	p := &idp{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

// serveTLS starts an HTTPS server and returns a client that trusts its
// certificate and nothing else.
func serveTLS(t *testing.T, h http.Handler) (*idp, *http.Client) {
	t.Helper()
	p := &idp{}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	pool := x509.NewCertPool()
	pool.AddCert(p.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	t.Cleanup(tr.CloseIdleConnections)
	return p, &http.Client{Transport: tr}
}

func staticBody(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// oidcClient builds a client for the OIDC provider testIssuer whose signing
// keys come from jwksURL.
func oidcClient(t *testing.T, jwksURL string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	cfg := oauth.Config{
		ClientID:    testClient,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   testIssuer,
			AuthURL:  "https://idp.example/auth",
			TokenURL: "https://idp.example/token",
			JWKSURL:  jwksURL,
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	c, err := oauth.New(silentProvider{}, cfg)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	return c
}

// jwksClient serves doc as the JWKS and returns a client verifying against it
// together with the server (for hit counts).
func jwksClient(t *testing.T, doc []byte) (*oauth.Client, *idp) {
	t.Helper()
	srv := serve(t, staticBody(doc))
	return oidcClient(t, srv.URL, nil), srv
}

// tokenClient builds an OIDC client whose token endpoint is tokenURL.
func tokenClient(t *testing.T, tokenURL string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	return oidcClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
		c.Provider.TokenURL = tokenURL
		if mut != nil {
			mut(c)
		}
	})
}

// userinfoClient builds a plain-OAuth2 client reading its profile from url.
func userinfoClient(t *testing.T, url string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	cfg := oauth.Config{
		ClientID:    testClient,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://idp.example/auth",
			TokenURL:    "https://idp.example/token",
			UserInfoURL: url,
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	c, err := oauth.New(silentProvider{}, cfg)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	return c
}

// ctx returns a context that bounds a single attack, so a regression that
// hangs fails the test instead of the run.
func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	return c
}

// verify is the one-line path "a token arrives at the callback".
func verify(t *testing.T, c *oauth.Client, token string) (*oauth.IDClaims, error) {
	t.Helper()
	return c.VerifyIDToken(ctx(t), token, testNonce)
}

// mustRejectToken fails unless err is the ErrIDTokenInvalid refusal.
func mustRejectToken(t *testing.T, got *oauth.IDClaims, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("hostile token ACCEPTED as %+v", got)
	}
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("hostile token failed, but not as ErrIDTokenInvalid: %v", err)
	}
}

// captureLogger records every line the library logs.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) record(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(msg, args...))
}
func (l *captureLogger) Debug(m string, a ...any) { l.record(m, a...) }
func (l *captureLogger) Info(m string, a ...any)  { l.record(m, a...) }
func (l *captureLogger) Warn(m string, a ...any)  { l.record(m, a...) }
func (l *captureLogger) Error(m string, a ...any) { l.record(m, a...) }
func (l *captureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
