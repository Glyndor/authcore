package idtoken_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

var errFuzzInvalid = errors.New("oauth: id token is invalid")

const (
	fuzzIssuer = "https://idp.example"
	fuzzClient = "client-fuzz"
	fuzzNonce  = "nonce-fuzz"
)

// fuzzKeys serves the one candidate whatever the kid and alg.
type fuzzKeys struct{ cand jwks.Candidate }

func (k fuzzKeys) CandidateFor(context.Context, string, string) (jwks.Candidate, error) {
	return k.cand, nil
}

var fuzzPrivate *ecdsa.PrivateKey

var (
	fuzzOnce  sync.Once
	fuzzPub   fuzzKeys
	fuzzValid string
)

// fuzzSetup signs a token with the fixture key. Its expiry
// is far in the future so the oracle does not depend on the clock.
func fuzzSetup(tb testing.TB) (fuzzKeys, string) {
	tb.Helper()
	fuzzOnce.Do(func() {
		// A fixed scalar keeps the fixture the same on every run.
		scalar := make([]byte, 32)
		scalar[31] = 42
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
		if err != nil {
			tb.Fatalf("parse key: %v", err)
		}
		fuzzPrivate = key
		tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, gjwt.MapClaims{
			"iss": fuzzIssuer, "aud": fuzzClient, "sub": "user-1", "nonce": fuzzNonce,
			"iat": time.Now().Add(-time.Hour).Unix(), "exp": time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		})
		tok.Header["kid"] = "k1"
		fuzzValid, err = tok.SignedString(key)
		if err != nil {
			tb.Fatalf("sign: %v", err)
		}
		fuzzPub = fuzzKeys{cand: jwks.Candidate{Pub: &key.PublicKey}}
	})
	return fuzzPub, fuzzValid
}

// FuzzVerify compares arbitrary compact tokens with an independent ES256 verifier.
func FuzzVerify(f *testing.F) {
	keys, valid := fuzzSetup(f)
	for _, control := range []byte{0, 1, 2, 4} {
		f.Add(fuzzIssuer+"\x00"+fuzzClient+"\x00user-1\x00"+string([]byte{control}), fuzzNonce)
	}
	f.Add(fuzzIssuer+"\x00"+fuzzClient+"\x00\x00\x00", fuzzNonce)
	f.Add(fuzzIssuer+"\x00"+fuzzClient+"\x00user-1\x00\x00", "wrong")
	f.Add(valid, fuzzNonce)
	f.Add(valid, "")
	f.Add(valid, fuzzNonce+"x")
	f.Add(valid+"=", fuzzNonce)
	f.Add("Bearer "+valid, fuzzNonce)
	// A second spelling of the same signature: the last character carries
	// unused bits, and a newline inside a segment is skipped by lenient decoders.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, valid[len(valid)-1])
	f.Add(valid[:len(valid)-1]+string(alphabet[last^1]), fuzzNonce)
	f.Add(valid[:40]+"\n"+valid[40:], fuzzNonce)
	f.Add(valid[:len(valid)-2]+"AA", fuzzNonce)
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", fuzzNonce)
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.AAAA", fuzzNonce)
	f.Add("a.b.c", "n")
	f.Add("..", "")
	f.Add("", "")

	p := idtoken.Params{ClientID: fuzzClient, Issuer: fuzzIssuer, Keys: keys, Invalid: errFuzzInvalid}
	f.Fuzz(func(t *testing.T, token, nonce string) {
		fields := strings.SplitN(token, "\x00", 4)
		if len(fields) == 4 && len(fields[3]) == 1 {
			verifyClaimMutation(t, keys, fields[0], fields[1], fields[2], nonce, int8(fields[3][0]/2), fields[3][0]%2 == 1)
			return
		}
		claims, err := idtoken.Verify(context.Background(), p, token, nonce)
		if (err == nil) != (referenceIDToken(token, nonce, &fuzzPrivate.PublicKey)) {
			t.Fatalf("verification = %v; reference accept=%v", err, referenceIDToken(token, nonce, &fuzzPrivate.PublicKey))
		}
		if err != nil {
			if !errors.Is(err, errFuzzInvalid) {
				t.Fatalf("a refusal that does not wrap the invalid sentinel: %v", err)
			}
			return
		}
		if claims.Subject != "user-1" || claims.Issuer != fuzzIssuer || len(claims.Audience) != 1 || claims.Audience[0] != fuzzClient {
			t.Fatalf("claims of the accepted token are off: %+v", claims)
		}
	})
}

// verifyClaimMutation signs every claim mutation using standard-library ECDSA.
func verifyClaimMutation(t *testing.T, keys fuzzKeys, issuer, audience, subject, nonce string, dates int8, list bool) {
	t.Helper()
	p := idtoken.Params{ClientID: fuzzClient, Issuer: fuzzIssuer, Keys: keys, Invalid: errFuzzInvalid}
	if !utf8.ValidString(subject) || len(issuer)+len(audience)+len(subject)+len(nonce) > 256 {
		return
	}
	var aud any = audience
	if list {
		aud = []string{audience}
	}
	// Dates stay far from the wall clock, including on slow machines.
	iat, exp := int64(1), int64(4102444800)
	if dates%3 == 1 {
		exp = 1
	}
	if dates%3 == 2 {
		iat = 4102444800
	}
	raw, err := json.Marshal(map[string]any{"iss": issuer, "aud": aud, "sub": subject, "nonce": nonce, "iat": iat, "exp": exp})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	input := b64([]byte(`{"alg":"ES256","kid":"k1"}`)) + "." + b64(raw)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, fuzzPrivate, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := input + "." + b64(sig)
	want := issuer == fuzzIssuer && audience == fuzzClient && subject != "" && nonce == fuzzNonce && exp > 1 && iat == 1
	claims, got := idtoken.Verify(context.Background(), p, token, fuzzNonce)
	if (got == nil) != want {
		t.Fatalf("verification=%v; reference accept=%v; payload=%s", got, want, raw)
	}
	if got == nil && (claims.Subject != subject || claims.Issuer != issuer || len(claims.Audience) != 1 || claims.Audience[0] != audience) {
		t.Fatal("claims changed")
	}
}

// referenceIDToken verifies the seeded ES256 domain without the production parser.
func referenceIDToken(token, nonce string, key *ecdsa.PublicKey) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || nonce == "" || len(token) > 16*1024 {
		return false
	}
	raw := make([][]byte, 3)
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != part {
			return false
		}
		raw[i] = b
	}
	var h map[string]any
	var c map[string]any
	if json.Unmarshal(raw[0], &h) != nil || json.Unmarshal(raw[1], &c) != nil || h["alg"] != "ES256" || len(raw[2]) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(raw[2][:32]), new(big.Int).SetBytes(raw[2][32:])) {
		return false
	}
	exp, eok := c["exp"].(float64)
	iat, iok := c["iat"].(float64)
	sub, _ := c["sub"].(string)
	return c["iss"] == fuzzIssuer && c["aud"] == fuzzClient && sub != "" && c["nonce"] == nonce && eok && iok && exp > float64(time.Now().Unix()) && iat <= float64(time.Now().Unix())
}
