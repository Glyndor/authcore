package exchange_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// FuzzRequestFidelity sends arbitrary client credentials, code and verifier
// through Do and reads the request back the way a compliant token endpoint
// does. The property: every value arrives as it was configured, under both
// client authentication methods, and no value adds a field, a header or a
// line to the request. RFC 6749 section 2.3.1 is the reference for the Basic
// encoding.
func FuzzRequestFidelity(f *testing.F) {
	f.Add("client", "secret", "code", "verifier", true)
	f.Add("id:colon", "pa ss+wo%rd", "c&grant_type=password", "v\r\nX-Evil: 1", true)
	f.Add("é", "日本語\x00", "\x00", "a=b", false)
	f.Add("", "s", "c", "v", false)

	f.Fuzz(func(t *testing.T, id, secret, code, verifier string, basic bool) {
		if secret == "" || code == "" || verifier == "" || len(code) > 8<<10 || len(verifier) > 128 {
			return // Do refuses these before any request; other targets cover that
		}
		got, form := sendRequest(id, secret, code, verifier, basic)
		if got == nil {
			t.Fatal("no request was sent")
		}
		for _, k := range []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier"} {
			if len(form[k]) != 1 {
				t.Fatalf("%s appears %d times", k, len(form[k]))
			}
		}
		if form.Get("code") != code || form.Get("code_verifier") != verifier || form.Get("client_id") != id ||
			form.Get("grant_type") != "authorization_code" || form.Get("redirect_uri") != "https://app.example/cb" {
			t.Fatalf("a field changed on the way: %v", form)
		}
		if got.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || len(got.Header) > 3 {
			t.Fatalf("unexpected headers: %v", got.Header)
		}
		if basic {
			checkBasic(t, got, form, id, secret)
			return
		}
		if form.Get("client_secret") != secret || got.Header.Get("Authorization") != "" || len(form) != 6 {
			t.Fatalf("post authentication is wrong: %v / %q", form, got.Header.Get("Authorization"))
		}
	})
}

// sendRequest runs Do against a transport that keeps the request it was given
// and its decoded body.
func sendRequest(id, secret, code, verifier string, basic bool) (*http.Request, url.Values) {
	var got *http.Request
	var form url.Values
	hc := &http.Client{Transport: fuzzRoundTrip(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		got = r
		return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})}
	method := "client_secret_post"
	if basic {
		method = "client_secret_basic"
	}
	p := exchange.Params{
		TokenURL: "https://idp.example/token", ClientID: id, RedirectURL: "https://app.example/cb",
		Secret: secret, AuthMethods: []string{method},
		Errs: exchange.Errors{Exchange: errFuzzExchange, NoIDToken: errFuzzNoID},
	}
	_, _ = exchange.Do(context.Background(), hc, p, code, verifier)
	return got, form
}

// checkBasic reads the Authorization header as RFC 6749 section 2.3.1 says a
// server does and compares what it finds with what was configured.
func checkBasic(t *testing.T, got *http.Request, form url.Values, id, secret string) {
	t.Helper()
	auth := got.Header.Get("Authorization")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil || !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("malformed Basic header %q: %v", auth, err)
	}
	rawID, rawSecret, ok := strings.Cut(string(raw), ":")
	gotID, err1 := url.QueryUnescape(rawID)
	gotSecret, err2 := url.QueryUnescape(rawSecret)
	if !ok || err1 != nil || err2 != nil || gotID != id || gotSecret != secret {
		t.Fatalf("a compliant server reads id=%q secret=%q from %q", gotID, gotSecret, raw)
	}
	if form.Has("client_secret") {
		t.Fatal("the secret is also in the body")
	}
}
