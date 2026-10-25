// Package urlcheck validates the URLs a provider configuration carries: https (loopback excepted) and no
// fragment on the authorization endpoint.
package urlcheck

import (
	"fmt"
	"net"
	"net/url"
	"strings"
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
		return fmt.Errorf("%s must not carry a fragment: %q", label, raw)
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
func RequireHTTPS(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	if u.Opaque != "" {
		return fmt.Errorf("%s is opaque, not a hierarchical URL: %q", label, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host, not a hierarchical URL: %q", label, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%s must use https (got %q in %q)", label, u.Scheme, raw)
}

// isLoopbackHost reports whether host is a loopback address (dev-only http).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	// Match the whole loopback range rather than the two literals people
	// usually type. 127.0.0.0/8 is all loopback, and a development server
	// bound to 127.0.0.2 to dodge a port collision is as local as 127.0.0.1.
	// Failing to recognise it refused the documented plaintext exception, so
	// this was a usability gap rather than a hole, but the definition should
	// be the one the standard library already has.
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
