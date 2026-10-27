package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type memoryTransport func(*http.Request) (*http.Response, error)

func (f memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fetchDocument(body string, failed func()) (Set, error) {
	h := &http.Client{Transport: memoryTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	return Get(context.Background(), h, "https://keys.example/jwks", errFetch, failed)
}

func TestGetRejectsAmbiguousKeysMember(t *testing.T) {
	key := `{"kty":"RSA","kid":"k","n":"` + rsaN + `","e":"AQAB"}`
	for _, name := range []string{"keys", "KEYS", "Keys", `ke\u0079s`} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%v", name, reverse), func(t *testing.T) {
				a, b := `[]`, `[`+key+`]`
				if reverse {
					a, b = b, a
				}
				body := `{"keys":` + a + `,"` + name + `":` + b + `}`
				failed := 0
				set, err := fetchDocument(body, func() { failed++ })
				if !errors.Is(err, errFetch) || len(set.Keys) != 0 || failed != 1 {
					t.Fatalf("Get = %+v, %v, failures=%d; want refusal and one failed attempt", set, err, failed)
				}
			})
		}
	}
	for _, name := range []string{"keys", "KEYS", `ke\u0079s`} {
		set, err := fetchDocument(`{"`+name+`":[`+key+`,`+key+`],"extra":{"keys":[]}}`, func() { t.Error("valid document counted as failure") })
		if err != nil || len(set.Keys["k"]) != 2 {
			t.Errorf("unambiguous document = %+v, %v; want two candidates under the same kid", set, err)
		}
	}
}
