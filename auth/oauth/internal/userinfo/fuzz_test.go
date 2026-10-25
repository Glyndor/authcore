package userinfo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/userinfo"
)

var errFuzzUserInfo = errors.New("oauth: userinfo request failed")

type fuzzRoundTrip func(*http.Request) (*http.Response, error)

func (f fuzzRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// FuzzFetch serves arbitrary bytes as a 200 userinfo answer. The property: no
// panic, every refusal wraps the userinfo sentinel, and an accepted profile is
// a non-empty JSON object with no "error" member, which an independent
// encoding/json decode of the same body agrees with.
func FuzzFetch(f *testing.F) {
	f.Add([]byte(`{"id":"42","login":"octo"}`))
	f.Add([]byte(`{"id":9007199254740993,"big":1e999999}`))
	f.Add([]byte(`{"error":"invalid_token"}`))
	f.Add([]byte(`{"id":"1"}garbage`))
	f.Add([]byte(`{"id":"1"}{"id":"2"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":[[[[[[[[[[1]]]]]]]]]]}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		hc := &http.Client{Transport: fuzzRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})}
		out, err := userinfo.Fetch(context.Background(), hc, "https://idp.example/userinfo", "token", errFuzzUserInfo)
		if err != nil {
			if !errors.Is(err, errFuzzUserInfo) {
				t.Fatalf("a refusal that does not wrap the userinfo sentinel: %v", err)
			}
			return
		}
		if len(out) == 0 {
			t.Fatal("accepted an empty profile")
		}
		if _, bad := out["error"]; bad {
			t.Fatal("accepted a profile that carries an error member")
		}
		var ref map[string]any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&ref); err != nil {
			t.Fatalf("accepted a body that encoding/json rejects: %v", err)
		}
		// Exactly one value: nothing but whitespace may follow it.
		rest := bytes.Trim(body[dec.InputOffset():], " \t\r\n")
		if len(rest) != 0 {
			t.Fatalf("accepted a body with %q after the profile", rest)
		}
		if len(ref) != len(out) {
			t.Fatalf("profile has %d members, an independent decode sees %d", len(out), len(ref))
		}
	})
}
