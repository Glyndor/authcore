package hostiletest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestKeysAndEncodings(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	a2, _ := hostiletest.RSAKeys()
	if a == nil || b == nil || a == b || a != a2 {
		t.Fatal("RSAKeys must return two distinct keys, stable across calls")
	}
	if got := hostiletest.B64([]byte{0xfb, 0xff}); got != "-_8" {
		t.Fatalf("B64 = %q, want unpadded base64url", got)
	}
	if got := hostiletest.B64Int(big.NewInt(65537)); got != "AQAB" {
		t.Fatalf("B64Int = %q", got)
	}
	jwk := hostiletest.RSAJWK("k", &a.PublicKey, map[string]any{"use": "sig"})
	if jwk["kty"] != "RSA" || jwk["kid"] != "k" || jwk["use"] != "sig" || jwk["e"] != "AQAB" {
		t.Fatalf("RSAJWK = %v", jwk)
	}
	if _, has := hostiletest.RSAJWK("", &a.PublicKey, nil)["kid"]; has {
		t.Fatal("an empty kid must be omitted")
	}
	checkECAndDocs(t, jwk, &a.PublicKey)
}

func checkECAndDocs(t *testing.T, jwk map[string]any, rsaPub *rsa.PublicKey) {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ej := hostiletest.ECJWK("e", "P-256", &ec.PublicKey, map[string]any{"alg": "ES256"})
	if ej["kty"] != "EC" || ej["crv"] != "P-256" || ej["kid"] != "e" || ej["alg"] != "ES256" {
		t.Fatalf("ECJWK = %v", ej)
	}
	if _, has := hostiletest.ECJWK("", "P-256", &ec.PublicKey, nil)["kid"]; has {
		t.Fatal("an empty kid must be omitted")
	}
	var doc struct{ Keys []map[string]any }
	if err := json.Unmarshal(hostiletest.JWKSDoc(jwk, ej), &doc); err != nil || len(doc.Keys) != 2 {
		t.Fatalf("JWKSDoc = %+v, %v", doc, err)
	}
	if string(hostiletest.StdJWKS(t)) != string(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, rsaPub, nil))) {
		t.Fatal("StdJWKS must publish the first key under KID")
	}
	want := sha256.Sum256([]byte("x"))
	if got := hostiletest.Digest(crypto.SHA256, []byte("x")); string(got) != string(want[:]) {
		t.Fatalf("Digest = %x", got)
	}
}

func TestClaimsOverrides(t *testing.T) {
	c := hostiletest.Claims(hostiletest.Nonce, map[string]any{"sub": "other", "email": nil})
	if c["sub"] != "other" || c["nonce"] != hostiletest.Nonce || c["iss"] != hostiletest.Issuer || c["aud"] != hostiletest.ClientID {
		t.Fatalf("claims = %v", c)
	}
	if _, has := c["email"]; has {
		t.Fatal("a nil override must delete the claim")
	}
	long := hostiletest.LongLived(map[string]any{"sub": "x"})
	if exp, _ := long["exp"].(int64); time.Unix(exp, 0).Before(time.Now().Add(71*time.Hour)) || long["sub"] != "x" {
		t.Fatalf("LongLived = %v", long)
	}
}

func TestMintEveryAlgorithm(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := hostiletest.Claims(hostiletest.Nonce, nil)
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "HS256", "HS384", "HS512", "none", "NONE"} {
		tok := hostiletest.Mint{Alg: alg, Key: a, EC: ec, HMAC: []byte("k"), Claims: claims}.String(t)
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("%s: token %q is not three segments", alg, tok)
		}
		if (alg == "none" || alg == "NONE") != (parts[2] == "") {
			t.Fatalf("%s: signature segment %q", alg, parts[2])
		}
	}
	hdr := func(m hostiletest.Mint) map[string]any {
		var h map[string]any
		raw := strings.Split(m.String(t), ".")[0]
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(b, &h) != nil {
			t.Fatalf("header %q: %v", raw, err)
		}
		return h
	}
	if h := hdr(hostiletest.Mint{Key: a}); h["kid"] != hostiletest.KID || h["alg"] != "RS256" || h["typ"] != "JWT" {
		t.Fatalf("default header = %v", h)
	}
	if _, has := hdr(hostiletest.Mint{Key: a, Kid: "-"})["kid"]; has {
		t.Fatal(`Kid "-" must omit the member`)
	}
	if h := hdr(hostiletest.Mint{Key: a, Kid: "z", Header: map[string]any{"x": 1, "typ": nil}}); h["kid"] != "z" || h["x"] != float64(1) || h["typ"] != nil {
		t.Fatalf("header = %v", h)
	}
}

func TestVerifyAcceptsSignedAndRejectsForged(t *testing.T) {
	srv := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.StdJWKS(t)))
	c := hostiletest.OIDCClient(t, srv.URL, nil)
	got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
	if err != nil || got == nil || got.Subject != "user-abc" {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	_, b := hostiletest.RSAKeys()
	forged := hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t)
	got, err = hostiletest.Verify(t, c, forged)
	hostiletest.MustRejectToken(t, got, err)
	if srv.Hits.Load() == 0 {
		t.Fatal("the JWKS endpoint was never fetched")
	}
	if hostiletest.Ctx(t).Err() != nil {
		t.Fatal("a fresh context must be live")
	}
}

// fetch GETs url with c and returns the status, the headers and the body.
func fetch(t *testing.T, c *http.Client, url string) (int, http.Header, []byte, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(hostiletest.Ctx(t), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body, err
}

func TestServers(t *testing.T) {
	srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{"a":1}`)))
	_, h, body, err := fetch(t, http.DefaultClient, srv.URL)
	if err != nil || string(body) != `{"a":1}` || h.Get("Content-Type") != "application/json" || srv.Hits.Load() != 1 {
		t.Fatalf("body %q type %q hits %d: %v", body, h.Get("Content-Type"), srv.Hits.Load(), err)
	}

	tls, client := hostiletest.ServeTLS(t, hostiletest.StaticBody([]byte(`{}`)))
	if _, _, _, err := fetch(t, client, tls.URL); err != nil {
		t.Fatalf("the TLS client must trust the test server: %v", err)
	}
	if _, _, _, err := fetch(t, http.DefaultClient, tls.URL); err == nil {
		t.Fatal("the default client must not trust the test certificate")
	}
	if tls.Hits.Load() != 1 {
		t.Fatalf("tls hits = %d", tls.Hits.Load())
	}
}

func TestDiscovery(t *testing.T) {
	doc := hostiletest.GoodDoc("https://x")
	for _, f := range hostiletest.EndpointFields {
		if doc[f] == nil {
			t.Fatalf("GoodDoc lacks %s", f)
		}
	}
	srv := hostiletest.DiscoveryServer(t, func(d map[string]any, base string) {
		d["token_endpoint"] = nil
		d["issuer"] = base + "/x"
	})
	_, _, body, err := fetch(t, http.DefaultClient, srv.URL)
	var got map[string]any
	if err != nil || json.Unmarshal(body, &got) != nil {
		t.Fatalf("discovery body %q: %v", body, err)
	}
	if got["issuer"] != srv.URL+"/x" || got["token_endpoint"] != nil || got["jwks_uri"] != srv.URL+"/jwks" {
		t.Fatalf("doc = %v", got)
	}
	plain := hostiletest.DiscoveryServer(t, nil)
	if code, _, _, err := fetch(t, http.DefaultClient, plain.URL); err != nil || code != 200 {
		t.Fatalf("plain discovery: %d %v", code, err)
	}

	hc := hostiletest.RemoteDiscovery(hostiletest.RemoteIssuer, func(d map[string]any) { d["jwks_uri"] = "x" })
	_, _, body, err = fetch(t, hc, hostiletest.RemoteIssuer+"/.well-known/openid-configuration")
	got = nil
	if err != nil || json.Unmarshal(body, &got) != nil {
		t.Fatalf("remote body %q: %v", body, err)
	}
	if got["jwks_uri"] != "x" || got["issuer"] != hostiletest.RemoteIssuer {
		t.Fatalf("remote doc = %v", got)
	}
}

func TestTokenBody(t *testing.T) {
	var got map[string]any
	body := hostiletest.TokenBody(map[string]string{"access_token": `a"b`, "expires_in": "raw:3600", "skip": ""})
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	if got["access_token"] != `a"b` || got["expires_in"] != float64(3600) {
		t.Fatalf("body = %v", got)
	}
	if _, has := got["skip"]; has {
		t.Fatal("an empty value must drop the key")
	}
}

func TestClientBuilders(t *testing.T) {
	jc, srv := hostiletest.JWKSClient(t, hostiletest.StdJWKS(t))
	if jc == nil || srv == nil {
		t.Fatal("JWKSClient returned nil")
	}
	touched := false
	if hostiletest.TokenClient(t, "https://idp.example/t", func(*oauth.Config) { touched = true }) == nil || !touched {
		t.Fatal("TokenClient must build a client and apply mut")
	}
	ui := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{"id":"7"}`)))
	uc := hostiletest.UserinfoClient(t, ui.URL, func(*oauth.Config) { touched = false })
	info, err := uc.UserInfo(hostiletest.Ctx(t), "tok")
	if err != nil || info["id"] != "7" || touched {
		t.Fatalf("UserInfo = %v, %v (mut applied: %v)", info, err, !touched)
	}
}

func TestLoggers(t *testing.T) {
	cl := &hostiletest.CaptureLogger{}
	p := hostiletest.SilentProvider{Log: cl}
	var _ authcore.Provider = p
	if p.Keys() != nil || !p.Config().EnableLogs {
		t.Fatal("unexpected provider")
	}
	p.Logger().Debug("d %d", 1)
	p.Logger().Info("i")
	p.Logger().Warn("w")
	p.Logger().Error("e")
	if got := cl.String(); got != "d 1\ni\nw\ne" {
		t.Fatalf("captured %q", got)
	}
	d := hostiletest.SilentProvider{}.Logger()
	d.Debug("x")
	d.Info("x")
	d.Warn("x")
	d.Error("x")
}
