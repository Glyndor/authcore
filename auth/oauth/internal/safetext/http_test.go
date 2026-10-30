package safetext_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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

// net/http refuses a Location it cannot parse and quotes the header whole in the
// error it returns, before any redirect policy runs. A relative target has no
// scheme, so the text can carry the Basic credential the provider just received
// in any encoding, escaped for a Go string or not.
func TestHTTPErrorDropsAnUnparseableLocationHeader(t *testing.T) {
	const id, secret = "client-123", `secret+canary"7401`
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id) + ":" + url.QueryEscape(secret)))
	for _, location := range []string{"/%zz/" + basic, "/%zz/" + url.QueryEscape(url.QueryEscape(url.QueryEscape(secret))), "/%zz/" + secret} {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 307, Header: http.Header{"Location": {location}}, Body: http.NoBody, Request: r}, nil
		})}
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://idp.example/token", strings.NewReader("x"))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "Location header") {
			t.Fatalf("net/http did not refuse the Location %q: %v", location, err)
		}
		got := safetext.HTTPError(err, id, secret)
		for current := got; current != nil; current = errors.Unwrap(current) {
			text := current.Error()
			for _, leaked := range []string{basic, secret, url.QueryEscape(secret), url.QueryEscape(url.QueryEscape(url.QueryEscape(secret))), "canary"} {
				if strings.Contains(text, leaked) {
					t.Fatalf("Location %q: credential form %q remains in %q", location, leaked, text)
				}
			}
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A provider or a proxy may write the percent escapes in lower case (%2b, %4b).
// Decoding only the upper-case ones would leave such an echo in the error. The
// second credential has capitals because a wrongly decoded lower-case digit
// lands on the same byte when the high nibble is 2, 6 or 7 (the 0x20 bit is
// already set there), so only a high nibble of 4 or 5 tells the two apart.
func TestHTTPErrorSeesALowercasePercentEncodedCredential(t *testing.T) {
	for credential, echoed := range map[string]string{"k+/s:e": "k%2b%2fs%3ae", "KMNO": "%4b%4d%4e%4f"} {
		cause := errors.New("provider echoed client_secret=" + echoed)
		got := safetext.HTTPError(&url.Error{Op: "Post", URL: "https://idp.example/token", Err: cause}, credential)
		for current := got; current != nil; current = errors.Unwrap(current) {
			if strings.Contains(current.Error(), echoed) {
				t.Fatalf("credential %q remains as %q in %q", credential, echoed, current.Error())
			}
		}
	}
}
