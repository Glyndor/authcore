package hostile_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

func TestHostile_IDToken_claimManipulation(t *testing.T) {
	over := func(o map[string]any) func(*testing.T) string {
		return func(t *testing.T) string { return signA(t, claims(testNonce, o)) }
	}
	now := time.Now()
	cases := []tokCase{
		{name: "control: everything valid", token: over(nil), accept: true},
		{name: "control: aud as a one-element array", token: over(map[string]any{"aud": []string{testClient}}), accept: true},
		{name: "control: azp equal to the client", token: over(map[string]any{"azp": testClient}), accept: true},
		{name: "control: nbf in the past", token: over(map[string]any{"nbf": now.Add(-time.Hour).Unix()}), accept: true},
	}
	add := func(name, why string, o map[string]any) {
		cases = append(cases, tokCase{name: name, why: why, token: over(o)})
	}

	for name, iss := range map[string]any{
		"other host": "https://evil.example", "trailing slash": testIssuer + "/", "upper-case host": "https://IDP.example",
		"http downgrade": "http://idp.example", "suffix domain": testIssuer + ".evil.example", "nul suffix": testIssuer + "\x00",
		"leading space": " " + testIssuer, "prefix extension": testIssuer + "/tenant", "number": 1, "array": []string{testIssuer},
		"object": map[string]string{"iss": testIssuer}, "null": jsonNull, "empty": "",
	} {
		add("iss "+name, "iss", map[string]any{"iss": iss})
	}
	add("iss missing", "iss", map[string]any{"iss": nil})

	for name, aud := range map[string]any{
		"another client": "client-999", "client plus third party": []string{testClient, "third-party"},
		"third party plus client": []string{"third-party", testClient}, "only a third party": []string{"third-party"},
		"empty array": []string{}, "number": 123, "array of numbers": []int{123}, "object": map[string]string{"a": testClient},
		"duplicate client": []string{testClient, testClient}, "trailing space": testClient + " ", "upper-case": "CLIENT-123",
		"null": jsonNull, "client then number": []any{testClient, 7},
	} {
		add("aud "+name, "aud", map[string]any{"aud": aud})
	}
	add("aud missing", "aud", map[string]any{"aud": nil})

	for name, azp := range map[string]any{
		"another client": "client-999", "empty": "", "number": 123, "null": jsonNull, "array": []string{testClient},
	} {
		add("azp "+name, "azp", map[string]any{"azp": azp})
	}

	for name, nonce := range map[string]any{
		"wrong": "nonce-other", "empty": "", "number": 123, "array": []string{testNonce}, "upper-case": strings.ToUpper(testNonce),
		"extended": testNonce + "x", "truncated": testNonce[:len(testNonce)-1], "null": jsonNull, "padded": testNonce + " ",
	} {
		add("nonce "+name, "nonce", map[string]any{"nonce": nonce})
	}
	add("nonce missing", "nonce", map[string]any{"nonce": nil})

	add("exp in the past", "expired", map[string]any{"exp": now.Add(-5 * time.Second).Unix()})
	add("exp is zero", "exp", map[string]any{"exp": 0})
	add("exp is negative", "expired", map[string]any{"exp": -1})
	add("exp missing", "exp", map[string]any{"exp": nil})
	add("exp as a string", "exp", map[string]any{"exp": fmt.Sprint(now.Add(time.Hour).Unix())})
	add("exp null", "exp", map[string]any{"exp": jsonNull})
	add("exp bool", "exp", map[string]any{"exp": true})
	add("exp array", "exp", map[string]any{"exp": []int64{now.Add(time.Hour).Unix()}})
	add("nbf in the future", "not valid yet", map[string]any{"nbf": now.Add(time.Hour).Unix()})
	add("nbf as a string", "nbf", map[string]any{"nbf": "0"})
	add("iat in the future", "issued", map[string]any{"iat": now.Add(time.Hour).Unix()})
	add("iat missing", "iat", map[string]any{"iat": nil})
	add("iat as a string", "iat", map[string]any{"iat": "1"})
	add("iat null", "iat", map[string]any{"iat": jsonNull})
	add("iat bool", "iat", map[string]any{"iat": true})
	add("sub missing", "subject", map[string]any{"sub": nil})
	add("sub empty", "subject", map[string]any{"sub": ""})
	add("sub number", "subject", map[string]any{"sub": 42})
	add("sub null", "subject", map[string]any{"sub": jsonNull})
	add("sub array", "subject", map[string]any{"sub": []string{"user-abc"}})

	runTokCases(t, cases)
}

// email_verified is the claim account-linking logic trusts. Anything that is
// not a clear "true" must come out false.
func TestHostile_IDToken_emailVerifiedFailsClosed(t *testing.T) {
	srvDoc := stdJWKS(t)
	for name, tc := range map[string]struct {
		val  any
		want bool
	}{
		"bool true": {true, true}, "string true": {"true", true},
		"string True": {"True", false}, "string TRUE": {"TRUE", false}, "yes": {"yes", false}, "one": {1, false},
		"string one": {"1", false}, "array": {[]bool{true}, false}, "object": {map[string]bool{"v": true}, false},
		"false": {false, false}, "string false": {"false", false}, "null": {jsonNull, false}, "padded": {" true", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := serve(t, staticBody(srvDoc))
			c := oidcClient(t, srv.URL, nil)
			got, err := verify(t, c, signA(t, claims(testNonce, map[string]any{"email_verified": tc.val})))
			if err != nil {
				t.Fatalf("a signed token with an odd email_verified is still a valid token: %v", err)
			}
			if got.EmailVerified != tc.want {
				t.Fatalf("EmailVerified = %v, want %v for %v", got.EmailVerified, tc.want, tc.val)
			}
		})
	}
}

// A signed token with a hostile payload shape must be refused without a panic.
func TestHostile_IDToken_payloadShapes(t *testing.T) {
	a, _ := rsaKeys()
	signRaw := func(t *testing.T, payload string) string {
		t.Helper()
		input := b64([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + b64([]byte(payload))
		sig, err := rsa.SignPKCS1v15(rand.Reader, a, crypto.SHA256, digest(crypto.SHA256, []byte(input)))
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + b64(sig)
	}
	deep := strings.Repeat("[", 3000) + strings.Repeat("]", 3000)
	valid, err := json.Marshal(claims(testNonce, nil))
	if err != nil {
		t.Fatal(err)
	}
	var cases []tokCase
	for name, payload := range map[string]string{
		"json array": `[]`, "json string": `"x"`, "json null": `null`, "json number": `123`, "empty": ``, "truncated object": `{"iss":"` + testIssuer,
		"claims object followed by junk": string(valid) + `garbage`, "two claims objects": string(valid) + string(valid),
	} {
		cases = append(cases, tokCase{name: name, token: func(t *testing.T) string { return signRaw(t, payload) }})
	}
	// Valid claims plus a deeply nested unused member: tolerated, and it must
	// not cost a panic or a stack overflow to find that out.
	nested := string(valid[:len(valid)-1]) + `,"x":` + deep + `}`
	cases = append(cases, tokCase{name: "control: valid claims with a deeply nested unused member", accept: true, token: func(t *testing.T) string { return signRaw(t, nested) }})
	runTokCases(t, cases)
}

func TestHostile_IDToken_sizeCapStopsBeforeAnyFetch(t *testing.T) {
	srv := serve(t, staticBody(stdJWKS(t)))
	c := oidcClient(t, srv.URL, nil)
	huge := signA(t, claims(testNonce, map[string]any{"pad": strings.Repeat("a", 17*1024)}))
	if len(huge) <= 16*1024 {
		t.Fatalf("test token is only %d bytes", len(huge))
	}
	got, err := verify(t, c, huge)
	mustRejectToken(t, got, err)
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("an oversized token still made the verifier fetch the JWKS %d time(s)", n)
	}
	// The same token under the cap is fine, proving the cap is what refused it.
	small := signA(t, claims(testNonce, map[string]any{"pad": strings.Repeat("a", 4*1024)}))
	if _, err := verify(t, c, small); err != nil {
		t.Fatalf("control token under the cap refused: %v", err)
	}
}

func TestHostile_IDToken_emptyNonceIsNeverAMatch(t *testing.T) {
	srv := serve(t, staticBody(stdJWKS(t)))
	c := oidcClient(t, srv.URL, nil)
	for name, claimNonce := range map[string]any{"token carries an empty nonce": "", "token carries a nonce": "x", "token carries none": nil} {
		tok := signA(t, claims("", map[string]any{"nonce": claimNonce}))
		if _, err := c.VerifyIDToken(ctx(t), tok, ""); err == nil {
			t.Errorf("%s: an empty expected nonce was accepted", name)
		}
	}
}

func TestHostile_IDToken_plainOAuth2ClientRefusesIDTokens(t *testing.T) {
	c := userinfoClient(t, "https://api.example/user", nil)
	_, err := c.VerifyIDToken(ctx(t), signA(t, claims(testNonce, nil)), testNonce)
	if err == nil {
		t.Fatal("a client with no issuer/JWKS accepted an id token")
	}
}

func TestHostile_IDToken_publicKeyCannotSignForAnotherClient(t *testing.T) {
	// A token minted for client A must not log a user into client B.
	srv := serve(t, staticBody(stdJWKS(t)))
	other := oidcClient(t, srv.URL, func(c *oauth.Config) { c.ClientID = "client-other" })
	tok := signA(t, claims(testNonce, nil))
	got, err := verify(t, other, tok)
	mustRejectToken(t, got, err)
}
