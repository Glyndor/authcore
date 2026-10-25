// Package redirect is the redirect policy and default HTTP client for every OAuth fetch: hop cap, https
// only, no private hosts, no cross-origin hop.
package redirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// Policy is what an OAuth fetch may reach. The zero value is the default:
// nothing internal, neither by a redirect nor by a connection.
type Policy struct {
	// AllowPrivate lifts the internal-destination checks, for an on-premises
	// provider.
	AllowPrivate bool
}

// GuardClient returns a shallow copy of non-nil c without mutating c, under
// the default Policy. See Policy.Guard.
func GuardClient(c *http.Client) *http.Client { return Policy{}.Guard(c) }

// NewClient returns the default HTTP client for OAuth fetches, under the
// default Policy. See Policy.NewClient.
func NewClient() *http.Client { return Policy{}.NewClient() }

// Check is the default Policy's redirect rule. See Policy.Check.
func Check(req *http.Request, via []*http.Request) error { return Policy{}.Check(req, via) }

// Guard returns a shallow copy of non-nil c without mutating c. The
// library's redirect rule applies first; the caller's CheckRedirect still
// applies to redirects that Check accepts. Timeout and Jar are preserved.
//
// Unless the Policy allows private destinations, the copy also gets the
// dial-time address check: a *http.Transport is cloned with its dialing
// wrapped (the caller's transport is not modified), and a nil Transport
// becomes the library's guarded default. A Transport of any other type cannot
// be inspected, so checking where it connects stays with its owner.
//
// A caller-supplied client whose Timeout is zero would remove the bound the
// default client carries, since http.Client.Do on a zero-timeout client
// blocks indefinitely on a hung provider. The library's 10-second default is
// reapplied in that case, so the supplied client cannot quietly disable the
// bound by clearing the field.
func (p Policy) Guard(c *http.Client) *http.Client {
	// Copy the client; replacing its callback previously discarded caller refusals.
	guarded := *c
	// checkRedirect preserves the caller's callback at the time of the copy.
	checkRedirect := c.CheckRedirect
	guarded.CheckRedirect = p.Check
	if checkRedirect != nil {
		guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := p.Check(req, via); err != nil {
				return err
			}
			return checkRedirect(req, via)
		}
	}
	if !p.AllowPrivate {
		guarded.Transport = netguard.Guard(c.Transport)
	}
	if guarded.Timeout == 0 {
		guarded.Timeout = 10 * time.Second
	}
	return &guarded
}

// NewClient returns the default HTTP client for OAuth fetches, with a
// 10-second timeout and Check as its redirect policy. Supplied clients
// receive the same policy through Guard before their own redirect rule.
func (p Policy) NewClient() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: p.Check}
	if !p.AllowPrivate {
		c.Transport = netguard.DefaultTransport()
	}
	return c
}

// Check is the redirect policy for every OAuth fetch (token, JWKS,
// userinfo, discovery). It refuses:
//   - more than a few hops,
//   - a downgrade to plaintext http,
//   - a redirect to a loopback / link-local / private IP address (SSRF to
//     cloud metadata or internal services), unless the Policy allows it,
//   - a cross-origin redirect — the token POST replays the client secret on
//     a 307/308, so it must never leave the configured host; legitimate
//     OAuth endpoints do not redirect across hosts,
//   - a same-origin redirect to a URL that carries credentials.
//
// A hop to the origin the request already talks to is accepted: a 307/308 on
// the token endpoint is the case it exists for. What a host name resolves to
// is checked when the client connects, not here.
func (p Policy) Check(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %s", safetext.Quote(req.URL.Redacted()))
	}
	if !p.AllowPrivate && internalLiteral(req.URL.Hostname()) {
		return fmt.Errorf("refusing redirect to private host %s", safetext.Quote(req.URL.Hostname()))
	}
	if !sameOrigin(via[len(via)-1].URL, req.URL) {
		return fmt.Errorf("refusing cross-origin redirect to %s", safetext.Quote(req.URL.Host))
	}
	if req.URL.User != nil {
		return fmt.Errorf("refusing redirect to a URL that carries credentials")
	}
	return nil
}

// internalLiteral reports whether host is an internal IP address written out.
// A name is not judged here: a redirect must stay on the origin it started
// from, and the connection check judges what a name resolves to.
func internalLiteral(host string) bool {
	a, ok := netguard.Literal(host)
	return ok && netguard.InternalAddr(a)
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
