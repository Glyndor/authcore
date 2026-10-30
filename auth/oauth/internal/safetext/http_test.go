package safetext_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

func TestHTTPErrorRedactsURLAndReflectedCauses(t *testing.T) {
	const credential = "canary+secret"
	for _, text := range []string{"unavailable", credential, url.QueryEscape(credential), url.PathEscape(credential)} {
		cause := errors.New(text)
		original := &url.Error{Op: "Post", URL: "https://idp.example/" + credential + "?echo=" + url.QueryEscape(credential), Err: cause}
		got := safetext.HTTPError(original, credential)
		if !errors.Is(got, cause) {
			t.Fatal("transport cause lost")
		}
		var cleaned *url.Error
		if !errors.As(got, &cleaned) || cleaned == original {
			t.Fatal("URL error was not copied")
		}
		if !strings.Contains(original.URL, credential) || original.Err != cause {
			t.Fatal("original error was mutated")
		}
		for current := got; current != nil; current = errors.Unwrap(current) {
			if strings.Contains(current.Error(), credential) || strings.Contains(current.Error(), url.QueryEscape(credential)) {
				t.Fatal("credential remains in error chain")
			}
		}
	}
}

func TestHTTPErrorKeepsTimeoutAndCancellation(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		got := safetext.HTTPError(&url.Error{Op: "Get", URL: "https://idp.example/", Err: cause}, "secret")
		if !errors.Is(got, cause) {
			t.Fatal("context cause lost")
		}
		var ue *url.Error
		if !errors.As(got, &ue) || ue.Timeout() != errors.Is(cause, context.DeadlineExceeded) {
			t.Fatalf("timeout changed: %v", got)
		}
	}
	cause := fmt.Errorf("secret: %w", context.DeadlineExceeded)
	got := safetext.HTTPError(&url.Error{Op: "Get", URL: "https://idp.example/", Err: cause}, "secret")
	var ue *url.Error
	if !errors.Is(got, context.DeadlineExceeded) || !errors.As(got, &ue) || !ue.Timeout() {
		t.Fatalf("redacted timeout lost: %v", got)
	}
	if safetext.HTTPError(nil) != nil {
		t.Fatal("nil became a failure")
	}
	if got := safetext.HTTPError(context.Canceled); got != context.Canceled {
		t.Fatal("non-URL error changed")
	}
}
