package idtoken_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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

var (
	fuzzOnce  sync.Once
	fuzzPub   fuzzKeys
	fuzzValid string
)

// fuzzSetup signs the one token the verifier is allowed to accept. Its expiry
// is far in the future so the oracle does not depend on the clock.
func fuzzSetup(tb testing.TB) (fuzzKeys, string) {
	tb.Helper()
	fuzzOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			tb.Fatalf("generate key: %v", err)
		}
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

// FuzzVerify feeds Verify arbitrary token and nonce strings. The verifier
// trusts exactly one signed token and one nonce, so the property is: it never
// panics, every refusal wraps the invalid sentinel, and nothing but that exact
// token under that exact nonce is ever accepted (no second spelling, no
// unsigned or re-signed variant, no claim tampered with).
func FuzzVerify(f *testing.F) {
	keys, valid := fuzzSetup(f)
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
		claims, err := idtoken.Verify(context.Background(), p, token, nonce)
		if err != nil {
			if !errors.Is(err, errFuzzInvalid) {
				t.Fatalf("a refusal that does not wrap the invalid sentinel: %v", err)
			}
			return
		}
		if token != valid || nonce != fuzzNonce {
			t.Fatalf("accepted a token that is not the signed one: token=%q nonce=%q", token, nonce)
		}
		if claims.Subject != "user-1" || claims.Issuer != fuzzIssuer || len(claims.Audience) != 1 || claims.Audience[0] != fuzzClient {
			t.Fatalf("claims of the accepted token are off: %+v", claims)
		}
	})
}
