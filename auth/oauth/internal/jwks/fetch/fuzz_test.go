package fetch_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/fetch"
)

// fuzzRSAN is the modulus of the RSA example key of RFC 7517 appendix A.1 (2048 bits).
const fuzzRSAN = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

var errFuzzFetch = errors.New("oauth: cannot obtain provider signing keys")

type fuzzRoundTrip func(*http.Request) (*http.Response, error)

func (f fuzzRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FuzzGet serves arbitrary bytes as a JWKS. The property: no panic, every
// refusal wraps the fetch sentinel, and every candidate in an accepted set is
// a key the verifier may use: an RSA key of 2048 to 16384 bits, or an EC key
// on a NIST curve, that is not published for encryption, and a key without a
// kid is only offered when it is the single key of the set.
func FuzzGet(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"` + fuzzRSAN + `","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","kid":"e1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"enc","use":"enc","n":"` + fuzzRSAN + `","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"small","use":"sig","n":"AQAB","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","use":"enc","kid":"k","n":"AQAB","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"oct","k":"AAAA"}]}`))
	f.Add([]byte(`{"keys":[null,1,"x",{}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`))
	f.Add([]byte(`{"keys":null}`))
	f.Add([]byte(`[]`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		hc := &http.Client{Transport: fuzzRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})}
		set, err := fetch.Get(context.Background(), hc, "https://idp.example/jwks", errFuzzFetch, func() {})
		if err != nil {
			if !errors.Is(err, errFuzzFetch) {
				t.Fatalf("a refusal that does not wrap the fetch sentinel: %v", err)
			}
			return
		}
		total := 0
		for kid, cands := range set.Keys {
			total += len(cands)
			for _, c := range cands {
				if c.Use != "" && c.Use != "sig" {
					t.Fatalf("kid %q: a key published for %q was made a candidate", kid, c.Use)
				}
				switch pub := c.Pub.(type) {
				case *rsa.PublicKey:
					if bits := pub.N.BitLen(); bits < 2048 || bits > 16384 || pub.E < 2 {
						t.Fatalf("kid %q: RSA key of %d bits, exponent %d", kid, bits, pub.E)
					}
				case *ecdsa.PublicKey:
					if _, err := pub.Bytes(); err != nil {
						t.Fatalf("kid %q: EC key is not a valid point: %v", kid, err)
					}
				default:
					t.Fatalf("kid %q: unexpected key type %T", kid, c.Pub)
				}
			}
		}
		if set.AnonAvailable && (total != 1 || len(set.Keys[""]) != 1) {
			t.Fatalf("an anonymous key is offered alongside others: %d candidates", total)
		}
		if !set.AnonAvailable && len(set.Keys[""]) != 0 {
			t.Fatal("a key without a kid is selectable although it is not the only key")
		}
	})
}
