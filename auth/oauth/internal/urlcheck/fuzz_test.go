package urlcheck_test

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
)

// FuzzRequireHTTPS puts arbitrary strings through both URL checks. Whatever is
// accepted must be a hierarchical URL with a host that is https, or plain http
// to a loopback host; and a URL accepted as fragment-free must contain no '#'.
// The loopback test uses net/netip, not the net.ParseIP of the code under test.
func FuzzRequireHTTPS(f *testing.F) {
	for _, seed := range []string{
		"https://idp.example/token", "http://idp.example/token", "http://localhost:8080/x", "http://127.0.0.2/x", "http://[::1]/x",
		"http://127.0.0.1.evil.example/", "http://localhost.evil.example/", "http://localhost@evil.example/", "https:opaque", "https:///x",
		"https://", "//idp.example", "javascript:alert(1)", "https://idp.example/a#frag", "https://idp.example/\n", "https://[::1", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if err := urlcheck.RequireHTTPS("url", raw); err == nil {
			// RequireNoFragment reports nothing for a string that does not
			// parse, because RequireHTTPS runs first and refuses it. The
			// no-fragment property therefore holds for what RequireHTTPS accepts.
			if err := urlcheck.RequireNoFragment("url", raw); err == nil && strings.Contains(raw, "#") {
				t.Fatalf("accepted %q as fragment-free", raw)
			}
			u, perr := url.Parse(raw)
			if perr != nil || u.Opaque != "" || u.Host == "" {
				t.Fatalf("accepted %q, which is not a hierarchical URL with a host", raw)
			}
			switch u.Scheme {
			case "https":
			case "http":
				addr, aerr := netip.ParseAddr(u.Hostname())
				if u.Hostname() != "localhost" && (aerr != nil || !addr.IsLoopback()) {
					t.Fatalf("accepted plain http to the non-loopback host %q", u.Hostname())
				}
			default:
				t.Fatalf("accepted the scheme %q in %q", u.Scheme, raw)
			}
		}
	})
}
