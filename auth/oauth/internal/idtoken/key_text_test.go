package idtoken

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
	gjwt "github.com/golang-jwt/jwt/v5"
)

type keyTextTransport func(*http.Request) (*http.Response, error)

func (f keyTextTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifySkipsJWKIdentifiersThatWouldBeRepaired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	x := base64.RawURLEncoding.EncodeToString(f.key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(f.key.Y.FillBytes(make([]byte, 32)))
	material := fmt.Sprintf(`"kty":"EC","crv":"P-256","x":%q,"y":%q`, x, y)
	for _, field := range []string{"kid", "issuer"} {
		for _, tc := range []struct {
			raw, text string
			valid     bool
		}{
			{`"\ud800"`, "�", false}, {"\"\xff\"", "�", false},
			{`"\ufffd"`, "�", true}, {`"�"`, "�", true}, {`"\ud83d\ude00"`, "😀", true},
		} {
			t.Run(fmt.Sprintf("%s/%q", field, tc.raw), func(t *testing.T) {
				kid, keyIssuer := tc.text, testIssuer
				metadata := `"kid":` + tc.raw
				if field == "issuer" {
					kid, keyIssuer = "k1", tc.text
					metadata = `"kid":"k1","issuer":` + tc.raw
				}
				body := `{"keys":[{` + material + `,` + metadata + `},{` + material + `,"kid":"spare"}]}`
				hc := &http.Client{Transport: keyTextTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})}
				p := f.params()
				p.Issuer = keyIssuer
				p.Keys = jwks.New("https://p.example/keys", hc, jwks.Errors{Fetch: errors.New("fetch"), Stale: errors.New("stale")})
				claims := goodClaims()
				claims["iss"] = keyIssuer
				tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, claims)
				tok.Header["kid"] = kid
				signed, err := tok.SignedString(f.key)
				if err != nil {
					t.Fatal(err)
				}
				got, err := Verify(context.Background(), p, signed, testNonce)
				if tc.valid {
					if err != nil || got == nil || got.Subject != "user-1" {
						t.Fatalf("valid key: claims=%+v, err=%v", got, err)
					}
				} else if got != nil || !errors.Is(err, errInvalid) {
					t.Fatalf("repaired key verified: claims=%+v, err=%v", got, err)
				}
				tok.Header["kid"] = "spare"
				signed, err = tok.SignedString(f.key)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(context.Background(), p, signed, testNonce); err != nil {
					t.Fatalf("usable sibling key discarded: %v", err)
				}
			})
		}
	}
}
