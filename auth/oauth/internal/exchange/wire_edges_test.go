package exchange_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
)

var (
	errExchange = errors.New("exchange failed")
	errNoID     = errors.New("no id token")
)

type stub func(*http.Request) (*http.Response, error)

func (f stub) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int, body string, seen *http.Request) *http.Client {
	return &http.Client{Transport: stub(func(r *http.Request) (*http.Response, error) {
		if seen != nil {
			*seen = *r
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
}

func params() exchange.Params {
	return exchange.Params{
		TokenURL: "https://provider.example/token", ClientID: "cid", RedirectURL: "https://app.example/cb",
		Errs: exchange.Errors{Exchange: errExchange, NoIDToken: errNoID},
	}
}

const okBody = `{"access_token":"at","token_type":"Bearer"}`

func TestDoAcceptsOnlySuccessStatuses(t *testing.T) {
	t.Parallel()
	for status, ok := range map[int]bool{199: false, 200: true, 299: true, 300: false, 301: false, 401: false} {
		_, err := exchange.Do(context.Background(), respond(status, okBody, nil), params(), "code", "verifier")
		if (err == nil) != ok {
			t.Errorf("status %d: accepted=%v, want %v (err=%v)", status, err == nil, ok, err)
		}
		if !ok && !errors.Is(err, errExchange) {
			t.Errorf("status %d: %v does not wrap the exchange sentinel", status, err)
		}
	}
}

func TestDoAsksForJSON(t *testing.T) {
	t.Parallel()
	var seen http.Request
	if _, err := exchange.Do(context.Background(), respond(200, okBody, &seen), params(), "code", "verifier"); err != nil {
		t.Fatal(err)
	}
	if got := seen.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q, want application/json", got)
	}
}

// The provider's own words are bounded before they reach an error message:
// 128 bytes of error code and 512 of description pass whole, one more is cut.
func TestDoBoundsTheProviderErrorText(t *testing.T) {
	t.Parallel()
	check := func(codeLen, descLen int) string {
		body := `{"error":"` + strings.Repeat("c", codeLen) + `","error_description":"` + strings.Repeat("d", descLen) + `"}`
		_, err := exchange.Do(context.Background(), respond(200, body, nil), params(), "code", "verifier")
		if !errors.Is(err, errExchange) {
			t.Fatalf("err = %v, want the exchange sentinel", err)
		}
		return err.Error()
	}
	if msg := check(128, 512); strings.Contains(msg, "…") {
		t.Errorf("text at the bounds must pass whole: %q", msg)
	}
	if msg := check(129, 1); !strings.Contains(msg, strings.Repeat("c", 128)+"…") {
		t.Errorf("a 129-byte code must be cut at 128: %q", msg)
	}
	if msg := check(1, 513); !strings.Contains(msg, strings.Repeat("d", 512)+"…") {
		t.Errorf("a 513-byte description must be cut at 512: %q", msg)
	}
}
