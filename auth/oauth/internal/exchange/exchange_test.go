package exchange

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var (
	errExchange  = errors.New("oauth: token exchange failed")
	errNoIDToken = errors.New("oauth: response contained no id_token")
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (brokenBody) Close() error             { return nil }

func respond(code int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

func params() Params {
	return Params{
		TokenURL:    "https://p.example/token",
		ClientID:    "client",
		RedirectURL: "https://app.example/cb",
		Secret:      "s3cret",
		Errs:        Errors{Exchange: errExchange, NoIDToken: errNoIDToken},
	}
}

const okBody = `{"access_token":"at","token_type":"Bearer","refresh_token":"rt","id_token":"it","expires_in":60}`

func TestDoSendsTheFormAndDecodesTheTokens(t *testing.T) {
	t.Parallel()
	var form url.Values
	var user, pass string
	var hasBasic bool
	h := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		user, pass, hasBasic = r.BasicAuth()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(okBody))}, nil
	})}

	// No advertised methods: the secret goes in the body.
	tok, err := Do(context.Background(), h, params(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if *tok != (Tokens{AccessToken: "at", TokenType: "Bearer", RefreshToken: "rt", IDToken: "it", ExpiresIn: 60}) {
		t.Errorf("tokens = %+v", *tok)
	}
	for k, want := range map[string]string{
		"grant_type": "authorization_code", "code": "the-code", "code_verifier": "the-verifier",
		"redirect_uri": "https://app.example/cb", "client_id": "client", "client_secret": "s3cret",
	} {
		if form.Get(k) != want {
			t.Errorf("form[%s] = %q, want %q", k, form.Get(k), want)
		}
	}
	if hasBasic {
		t.Error("post method also sent a Basic header")
	}

	// Basic advertised: the secret goes in the header, form-encoded, not the body.
	p := params()
	p.AuthMethods = []string{"client_secret_basic"}
	p.ClientID, p.Secret = "a:b", "p+w/"
	if _, err := Do(context.Background(), h, p, "c", "v"); err != nil {
		t.Fatalf("Do basic: %v", err)
	}
	if !hasBasic || user != url.QueryEscape("a:b") || pass != url.QueryEscape("p+w/") {
		t.Errorf("basic credentials = %q/%q (present=%v)", user, pass, hasBasic)
	}
	if form.Has("client_secret") {
		t.Error("basic method leaked the secret into the body")
	}
}

func TestDoUsesTheSecretFunction(t *testing.T) {
	t.Parallel()
	p := params()
	p.Secret = ""
	p.SecretFunc = func(context.Context) (string, error) { return "from-func", nil }
	var got string
	h := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		got = v.Get("client_secret")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(okBody))}, nil
	})}
	if _, err := Do(context.Background(), h, p, "c", "v"); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != "from-func" {
		t.Errorf("client_secret = %q, want from-func", got)
	}
}

func TestDoRefusals(t *testing.T) {
	t.Parallel()
	withFunc := func(f func(context.Context) (string, error)) Params {
		p := params()
		p.Secret, p.SecretFunc = "", f
		return p
	}
	oidc := params()
	oidc.RequireIDToken = true
	unsupported := params()
	unsupported.AuthMethods = []string{"private_key_jwt"}
	badURL := params()
	badURL.TokenURL = "http://\x7f/token"

	tests := []struct {
		name     string
		p        Params
		code     string
		verifier string
		client   *http.Client
		want     string
		sentinel error
	}{
		{"empty code", params(), "", "v", respond(200, okBody), "code must not be empty", errExchange},
		{"empty verifier", params(), "c", "", respond(200, okBody), "code_verifier must not be empty", errExchange},
		{"secret function fails", withFunc(func(context.Context) (string, error) { return "", errors.New("kms down") }),
			"c", "v", respond(200, okBody), "client secret function failed: kms down", errExchange},
		{"secret function returns empty", withFunc(func(context.Context) (string, error) { return "", nil }),
			"c", "v", respond(200, okBody), "returned an empty secret", errExchange},
		{"unsupported client auth", unsupported, "c", "v", respond(200, okBody), "no supported client auth method", errExchange},
		{"unbuildable request", badURL, "c", "v", respond(200, okBody), "build request", errExchange},
		{"transport error", params(), "c", "v", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})}, "dial failed", errExchange},
		{"read error", params(), "c", "v", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: brokenBody{}}, nil
		})}, "read response", errExchange},
		{"non-2xx", params(), "c", "v", respond(400, okBody), "status 400", errExchange},
		{"not json", params(), "c", "v", respond(200, `nope`), "decode response", errExchange},
		{"null body", params(), "c", "v", respond(200, `null`), "empty response", errExchange},
		{"error with description", params(), "c", "v", respond(200, `{"error":"invalid_grant","error_description":"expired"}`),
			"provider returned invalid_grant: expired", errExchange},
		{"error without description", params(), "c", "v", respond(200, `{"error":"invalid_grant"}`),
			"provider returned invalid_grant", errExchange},
		{"error description is capped", params(), "c", "v", respond(200, `{"error":"x","error_description":"`+strings.Repeat("a", 600)+`"}`),
			strings.Repeat("a", exchangeErrorMaxLen) + "…", errExchange},
		{"wrong field types", params(), "c", "v", respond(200, `{"access_token":5}`), "decode response", errExchange},
		{"missing access token", params(), "c", "v", respond(200, `{"token_type":"Bearer"}`), "missing access_token or token_type", errExchange},
		{"missing token type", params(), "c", "v", respond(200, `{"access_token":"a"}`), "missing access_token or token_type", errExchange},
		{"OIDC without id_token", oidc, "c", "v", respond(200, `{"access_token":"a","token_type":"Bearer"}`), "no id_token", errNoIDToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Do(context.Background(), tc.client, tc.p, tc.code, tc.verifier)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want errors.Is(..., %v)", err, tc.sentinel)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDoAcceptsAPlainOAuth2ResponseWithoutAnIDToken(t *testing.T) {
	t.Parallel()
	tok, err := Do(context.Background(), respond(200, `{"access_token":"a","token_type":"bearer"}`), params(), "c", "v")
	if err != nil || tok.AccessToken != "a" {
		t.Fatalf("Do = %+v, %v", tok, err)
	}
}
