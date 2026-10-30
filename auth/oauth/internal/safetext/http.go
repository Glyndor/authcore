package safetext

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// urlText matches a URL as it appears inside a diagnostic.
var urlText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S*`)

// HTTPError removes the request URL from a transport failure. Redirect targets
// can reflect credentials in any URL component, and redirect-policy errors can
// repeat the target too. Safe causes remain available through errors.Is.
func HTTPError(err error, credentials ...string) error {
	var original *url.Error
	if !errors.As(err, &original) {
		return err
	}
	cleaned := *original
	cleaned.URL = "[redacted]"
	if original.Err != nil {
		text := original.Err.Error()
		// URLs are dropped from the cause, so the refusal reason stays readable
		// while a target that carries a credential is never repeated.
		scrubbed := urlText.ReplaceAllString(text, "[redacted-url]")
		if scrubbed != text || echoesCredential(scrubbed, credentials) {
			if echoesCredential(scrubbed, credentials) {
				scrubbed = "HTTP request failed"
			}
			cleaned.Err = hiddenCause{cause: original.Err, text: scrubbed}
		}
	}
	return &cleaned
}

func echoesCredential(text string, credentials []string) bool {
	decoded, _ := url.QueryUnescape(text)
	path, _ := url.PathUnescape(text)
	for _, credential := range credentials {
		if credential != "" && (strings.Contains(text, credential) || strings.Contains(decoded, credential) || strings.Contains(path, credential)) {
			return true
		}
	}
	return false
}

// Keep the cause queryable without exposing its credential-bearing text via
// Unwrap. url.Error uses Timeout to report the underlying failure's timeout.
type hiddenCause struct {
	cause error
	text  string
}

func (e hiddenCause) Error() string { return e.text }

func (e hiddenCause) Is(target error) bool { return errors.Is(e.cause, target) }

func (e hiddenCause) Timeout() bool {
	var timeout interface{ Timeout() bool }
	return errors.As(e.cause, &timeout) && timeout.Timeout()
}

func (e hiddenCause) Temporary() bool {
	var temporary interface{ Temporary() bool }
	return errors.As(e.cause, &temporary) && temporary.Temporary()
}
