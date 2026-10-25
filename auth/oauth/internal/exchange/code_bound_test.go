package exchange

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDoRefusesACodeOverTheBound(t *testing.T) {
	t.Parallel()
	called := false
	h := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(okBody))}, nil
	})}
	if _, err := Do(context.Background(), h, params(), strings.Repeat("c", authCodeMaxLen+1), "v"); !errors.Is(err, errExchange) {
		t.Fatalf("over the bound: err = %v", err)
	}
	if called {
		t.Fatal("an oversized code reached the transport")
	}
	if _, err := Do(context.Background(), h, params(), strings.Repeat("c", authCodeMaxLen), "v"); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
}
