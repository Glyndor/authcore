package idtoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

var errInvalid = errors.New("oauth: id token is invalid")

const (
	testIssuer   = "https://p.example"
	testClientID = "client-1"
	testNonce    = "n-0S6_WzA2Mj"
)

// fixedKeys serves one candidate whatever the kid and alg.
type fixedKeys struct {
	cand jwks.Candidate
	err  error
}

func (f fixedKeys) CandidateFor(context.Context, string, string) (jwks.Candidate, error) {
	return f.cand, f.err
}

type fixture struct {
	key  *ecdsa.PrivateKey
	keys fixedKeys
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return fixture{key: k, keys: fixedKeys{cand: jwks.Candidate{Pub: &k.PublicKey}}}
}

func goodClaims() gjwt.MapClaims {
	now := time.Now()
	return gjwt.MapClaims{
		"iss":            testIssuer,
		"sub":            "user-1",
		"aud":            testClientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          testNonce,
		"email":          "a@example.com",
		"email_verified": true,
		"name":           "Ada",
	}
}

func (f fixture) sign(t *testing.T, claims gjwt.MapClaims) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (f fixture) params() Params {
	return Params{ClientID: testClientID, Issuer: testIssuer, Keys: f.keys, Invalid: errInvalid}
}

func TestVerifyReturnsTheValidatedClaims(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	got, err := Verify(context.Background(), f.params(), f.sign(t, goodClaims()), testNonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "user-1" || got.Issuer != testIssuer || got.Email != "a@example.com" || !got.EmailVerified ||
		got.Name != "Ada" || len(got.Audience) != 1 || got.Audience[0] != testClientID || got.Raw["sub"] != "user-1" {
		t.Errorf("claims = %+v", got)
	}
}

func TestVerifyWithAValidatorIgnoresTheFixedIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := f.params()
	p.Issuer = ""
	p.Validator = func(iss string) bool { return iss == testIssuer }
	if _, err := Verify(context.Background(), p, f.sign(t, goodClaims()), testNonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	p.Validator = func(string) bool { return false }
	_, err := Verify(context.Background(), p, f.sign(t, goodClaims()), testNonce)
	if !errors.Is(err, errInvalid) || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("validator refusal: %v", err)
	}
	noIss := goodClaims()
	delete(noIss, "iss")
	p.Validator = func(string) bool { return true }
	if _, err := Verify(context.Background(), p, f.sign(t, noIss), testNonce); !errors.Is(err, errInvalid) {
		t.Fatalf("token without iss: %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	mut := func(fn func(gjwt.MapClaims)) string {
		c := goodClaims()
		fn(c)
		return f.sign(t, c)
	}
	noIssuer := f.params()
	noIssuer.Issuer = ""
	failingKeys := f.params()
	failingKeys.Keys = fixedKeys{err: errors.New("no such key")}
	restricted := f.params()
	restricted.Keys = fixedKeys{cand: jwks.Candidate{Pub: &f.key.PublicKey, Issuer: "https://other.example"}}

	tests := []struct {
		name  string
		p     Params
		token string
		nonce string
		want  string
	}{
		{"empty nonce", f.params(), f.sign(t, goodClaims()), "", "no nonce supplied"},
		{"oversized token", f.params(), strings.Repeat("a", maxIDTokenLen+1), testNonce, "token too large"},
		{"non-compact characters", f.params(), "a.b\n.c", testNonce, "outside the base64url alphabet"},
		{"no issuer configured", noIssuer, f.sign(t, goodClaims()), testNonce, "no issuer configured"},
		{"key lookup fails", failingKeys, f.sign(t, goodClaims()), testNonce, "no such key"},
		{"key restricted to another issuer", restricted, f.sign(t, goodClaims()), testNonce, "restricted to"},
		{"wrong issuer", f.params(), mut(func(c gjwt.MapClaims) { c["iss"] = "https://evil.example" }), testNonce, "issuer"},
		{"expired", f.params(), mut(func(c gjwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), testNonce, "expired"},
		{"nonce mismatch", f.params(), f.sign(t, goodClaims()), "other", "nonce mismatch"},
		{"missing nonce claim", f.params(), mut(func(c gjwt.MapClaims) { delete(c, "nonce") }), testNonce, "nonce mismatch"},
		{"two audiences", f.params(), mut(func(c gjwt.MapClaims) { c["aud"] = []string{testClientID, "other"} }), testNonce, "audience"},
		{"azp names another client", f.params(), mut(func(c gjwt.MapClaims) { c["azp"] = "other" }), testNonce, "azp does not match"},
		{"azp not a string", f.params(), mut(func(c gjwt.MapClaims) { c["azp"] = 5 }), testNonce, "azp does not match"},
		{"missing iat", f.params(), mut(func(c gjwt.MapClaims) { delete(c, "iat") }), testNonce, "iat"},
		{"non-numeric iat", f.params(), mut(func(c gjwt.MapClaims) { c["iat"] = "now" }), testNonce, "iat"},
		{"missing subject", f.params(), mut(func(c gjwt.MapClaims) { delete(c, "sub") }), testNonce, "missing subject"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(context.Background(), tc.p, tc.token, tc.nonce)
			if !errors.Is(err, errInvalid) {
				t.Fatalf("err = %v, want errors.Is(..., errInvalid)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestVerifyAcceptsAnAzpEqualToTheClientID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := goodClaims()
	c["azp"] = testClientID
	if _, err := Verify(context.Background(), f.params(), f.sign(t, c), testNonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
