package exchange_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
)

var (
	errFuzzExchange = errors.New("oauth: token exchange failed")
	errFuzzNoID     = errors.New("oauth: response contained no id_token")
)

type fuzzRoundTrip func(*http.Request) (*http.Response, error)

func (f fuzzRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FuzzDo serves arbitrary bytes as a 200 token-endpoint answer to an OIDC
// client. The property: no panic, every refusal wraps one of the two
// sentinels, and accepted tokens come from a JSON object that carries no
// "error" member, with a non-empty access_token, token_type and id_token.
func FuzzDo(f *testing.F) {
	f.Add([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"x.y.z","expires_in":3600}`))
	f.Add([]byte(`{"error":"invalid_grant","error_description":"expired"}`))
	f.Add([]byte(`{"error":null,"access_token":"a","token_type":"Bearer","id_token":"i"}`))
	f.Add([]byte(`{"access_token":"a","token_type":"Bearer"}`))
	f.Add([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"i","expires_in":1e999}`))
	f.Add([]byte(`{"access_token":"","token_type":"Bearer","id_token":"i"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"access_token":"a"}garbage`))
	f.Add([]byte{})

	p := exchange.Params{
		TokenURL: "https://idp.example/token", ClientID: "client", RedirectURL: "https://app.example/cb",
		Secret: "s3cr3t", RequireIDToken: true,
		Errs: exchange.Errors{Exchange: errFuzzExchange, NoIDToken: errFuzzNoID},
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		hc := &http.Client{Transport: fuzzRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})}
		tok, err := exchange.Do(context.Background(), hc, p, "code", "verifier")
		if err != nil {
			if !errors.Is(err, errFuzzExchange) && !errors.Is(err, errFuzzNoID) {
				t.Fatalf("a refusal that wraps neither sentinel: %v", err)
			}
			return
		}
		if tok.AccessToken == "" || tok.TokenType == "" || tok.IDToken == "" {
			t.Fatalf("accepted an incomplete token set: %+v", tok)
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(body, &probe); err != nil {
			t.Fatalf("accepted a body that encoding/json rejects: %v", err)
		}
		if _, bad := probe["error"]; bad {
			t.Fatal("accepted tokens from an answer that carries an error member")
		}
	})
}
