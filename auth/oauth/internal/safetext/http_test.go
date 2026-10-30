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

// A stray "%zz" made url.QueryUnescape fail on the whole text, so a credential
// the provider echoed percent-encoded, once or twice, escaped the check.
func TestHTTPErrorSeesAnEncodedCredentialBesideBrokenEscapes(t *testing.T) {
	const credential = "canary+secret/7"
	once := url.QueryEscape(credential)
	twice := url.QueryEscape(once)
	for name, text := range map[string]string{
		"broken escape first": "%zz " + once,
		"double encoded":      "bad %zz then " + twice,
		"plus for space":      "q=" + strings.ReplaceAll("canary secret/7", " ", "+"),
	} {
		t.Run(name, func(t *testing.T) {
			cause := errors.New(text)
			got := safetext.HTTPError(&url.Error{Op: "Post", URL: "https://idp.example/", Err: cause}, credential, "canary secret/7")
			for current := got; current != nil; current = errors.Unwrap(current) {
				for _, leaked := range []string{credential, once, twice, "canary+secret/7", "canary secret/7"} {
					if strings.Contains(current.Error(), leaked) {
						t.Fatalf("credential form %q remains in %q", leaked, current.Error())
					}
				}
			}
		})
	}
}

// A form field writes a space as "+" and a real plus as "%2B". Turning every
// "+" into a space after decoding lost the real one, so a credential that held
// both was echoed in a form the check did not build.
func TestHTTPErrorSeesACredentialWithASpaceAndAPlus(t *testing.T) {
	const credential = "canary secret+7"
	echoed := "q=" + strings.ReplaceAll(url.QueryEscape(credential), "%20", "+")
	cause := errors.New(echoed)
	got := safetext.HTTPError(&url.Error{Op: "Post", URL: "https://idp.example/", Err: cause}, credential)
	for current := got; current != nil; current = errors.Unwrap(current) {
		if strings.Contains(current.Error(), echoed) || strings.Contains(current.Error(), credential) {
			t.Fatalf("credential remains in %q", current.Error())
		}
	}
}
