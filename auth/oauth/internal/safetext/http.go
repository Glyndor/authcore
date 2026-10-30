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
	// A stray "%zz" makes url.QueryUnescape give up on the whole text, so the
	// forms are built by a decoder that skips what it cannot read. Two rounds
	// cover a credential that a proxy encoded twice.
	once := percentDecode(text)
	twice := percentDecode(once)
	// A form field writes a space as "+" and a real plus as "%2B", so the plus
	// is turned into a space before each decode round, never after: afterwards
	// the two can no longer be told apart.
	plusOnce := percentDecode(strings.ReplaceAll(text, "+", " "))
	plusTwice := percentDecode(strings.ReplaceAll(plusOnce, "+", " "))
	forms := []string{text, once, twice, plusOnce, plusTwice}
	for _, credential := range credentials {
		if credential == "" {
			continue
		}
		for _, form := range forms {
			if strings.Contains(form, credential) {
				return true
			}
		}
	}
	return false
}

// percentDecode decodes every well-formed %XX escape in s and leaves the rest
// as it is.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
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
