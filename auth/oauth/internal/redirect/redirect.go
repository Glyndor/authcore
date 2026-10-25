// Package redirect is the redirect policy and default HTTP client for every OAuth fetch: hop cap, https
// only, no private hosts, no cross-origin hop.
package redirect

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GuardClient returns a shallow copy of non-nil c without mutating c. The
// library's redirect rule applies first; the caller's CheckRedirect still
// applies to redirects that Check accepts. Transport, Timeout and Jar
// are preserved.
//
// A caller-supplied client whose Timeout is zero would remove the bound the
// default client carries, since http.Client.Do on a zero-timeout client
// blocks indefinitely on a hung provider. The library's 10-second default is
// reapplied in that case, so the supplied client cannot quietly disable the
// bound by clearing the field.
func GuardClient(c *http.Client) *http.Client {
	// Copy the client; replacing its callback previously discarded caller refusals.
	guarded := *c
	// checkRedirect preserves the caller's callback at the time of the copy.
	checkRedirect := c.CheckRedirect
	guarded.CheckRedirect = Check
	if checkRedirect != nil {
		guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := Check(req, via); err != nil {
				return err
			}
			return checkRedirect(req, via)
		}
	}
	if guarded.Timeout == 0 {
		guarded.Timeout = 10 * time.Second
	}
	return &guarded
}

// NewClient returns the default HTTP client for OAuth fetches, with a
// 10-second timeout and Check as its redirect policy. Supplied clients
// receive the same policy through GuardClient before their own redirect rule.
func NewClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: Check}
}

// Check is the redirect policy for every OAuth fetch (token, JWKS,
// userinfo, discovery). It refuses:
//   - more than a few hops,
//   - a downgrade to plaintext http,
//   - a redirect to a loopback / link-local / private host (SSRF to cloud
//     metadata or internal services),
//   - a cross-origin redirect — the token POST replays the client secret on a
//     307/308, so it must never leave the configured host; legitimate OAuth
//     endpoints do not redirect across hosts.
func Check(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %q", req.URL.Redacted())
	}
	if isPrivateHost(req.URL.Hostname()) {
		return fmt.Errorf("refusing redirect to private host %q", req.URL.Hostname())
	}
	prev := via[len(via)-1]
	if !sameOrigin(prev.URL, req.URL) {
		return fmt.Errorf("refusing cross-origin redirect to %q", req.URL.Host)
	}
	return nil
}

// sameOrigin reports whether a and b refer to the same scheme/host/port. It
// compares the host case-insensitively (Hostnames are case-insensitive per
// RFC 3986 §3.2.2) and the port by its effective value: an unset or default
// port is treated as the scheme's default, so https://provider.example and
// https://provider.example:443 are the same origin.
func sameOrigin(a, b *url.URL) bool {
	if a.Scheme != b.Scheme {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

// effectivePort returns port as a string, defaulting to the scheme's standard
// port when not set. Comparing two unspecified ports this way means
// https://provider.example and https://provider.example:443 do not look like
// a cross-origin move and stay on the same origin.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// isPrivateHost reports whether host is an IP literal in a loopback, private,
// link-local, or unspecified range. Hostnames (non-literals) return false — the
// scheme and cross-origin checks still apply, and the initial endpoint was
// https-validated.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
