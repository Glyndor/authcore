// Package urlcheck validates the URLs a provider configuration carries: https (loopback excepted), no
// credentials, no internal destination, and no fragment on the authorization endpoint.
package urlcheck

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// RequireNoFragment rejects a URL whose fragment is non-empty. The OIDC
// authorization endpoint is expected to consume query parameters; anything
// after '#' never reaches the server.
func RequireNoFragment(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Parsing failures are reported by RequireHTTPS, which runs first.
		return nil
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%s must not carry a fragment: %s", label, safetext.Quote(raw))
	}
	return nil
}

// RequireHTTPS rejects a URL whose scheme is not https. Plain http is allowed
// only for an explicit loopback host (local development), and that is the loud
// exception — the secure transport is the default everywhere else.
//
// Opaque URLs (https:opaque, https:?query) and https URLs with no host
// (https:///path) parse without erroring but cannot be reached. They were
// accepted by validation and only failed later, when the fetch ran, so the
// caller had no signal that the config was unworkable. Both are refused here.
//
// A URL that carries credentials (https://user:pass@host) is refused as well:
// they would ride along as a Basic Authorization header on every request to
// it and into any log line that prints the URL. The message does not repeat
// them.
func RequireHTTPS(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			// The wrapped error repeats the whole URL; keep only the cause.
			err = ue.Err
		}
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	if u.Opaque != "" {
		return fmt.Errorf("%s is opaque, not a hierarchical URL: %s", label, safetext.Quote(raw))
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host, not a hierarchical URL: %s", label, safetext.Quote(raw))
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry credentials in the URL", label)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%s must use https (got %s in %s)", label, safetext.Quote(u.Scheme), safetext.Quote(raw))
}

// RequireExternal rejects a URL whose host is an internal destination: a
// loopback, private, link-local, unspecified or cloud-metadata address, or a
// name that always points inside. A loopback host passes when allowLoopback is
// set, which is the development exception. It checks the host as written; a
// name that merely resolves inward is caught when the client connects.
func RequireExternal(label, raw string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		// RequireHTTPS reports parse failures.
		return nil
	}
	host := u.Hostname()
	if isLoopbackHost(host) {
		if allowLoopback {
			return nil
		}
	} else if !netguard.InternalHost(host) {
		return nil
	}
	return fmt.Errorf("%s points at an internal address (%s); set AllowPrivateNetwork if the provider really lives there", label, safetext.Quote(host))
}

// isLoopbackHost reports whether host is a loopback address (dev-only http).
// It matches the whole loopback range rather than the two literals people
// usually type: 127.0.0.0/8 is all loopback, and a development server bound
// to 127.0.0.2 to dodge a port collision is as local as 127.0.0.1.
func isLoopbackHost(host string) bool { return netguard.Loopback(host) }
