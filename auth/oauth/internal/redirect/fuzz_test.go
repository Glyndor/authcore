package redirect_test

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/redirect"
)

// fuzzPrivate is the "do not follow a redirect there" rule for an IP literal,
// written with net/netip instead of the net.ParseIP the code under test uses.
func fuzzPrivate(host string) bool {
	if strings.Contains(host, "%") {
		return false // a zone is not an address the library claims to parse
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified()
}

func fuzzPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// FuzzCheck puts two arbitrary URLs and a hop count through the redirect
// policy. Whenever it follows, the target must be https, not an internal IP
// literal, on the same host and port as the previous hop, and the hop count
// must be under the cap.
func FuzzCheck(f *testing.F) {
	f.Add("https://idp.example/token", "https://idp.example/other", uint8(1))
	f.Add("https://idp.example/token", "https://idp.example:443/other", uint8(1))
	f.Add("https://idp.example/token", "http://idp.example/other", uint8(1))
	f.Add("https://idp.example/token", "https://evil.example/", uint8(1))
	f.Add("https://idp.example/token", "https://127.0.0.1/", uint8(1))
	f.Add("https://idp.example/token", "https://[::ffff:127.0.0.1]/", uint8(1))
	f.Add("https://127.0.0.1/token", "https://127.0.0.1/other", uint8(1))
	f.Add("https://IDP.example/token", "https://idp.EXAMPLE/other", uint8(4))
	f.Add("https://idp.example/token", "https://idp.example/other", uint8(5))
	f.Add("https://u@idp.example/token", "//idp.example/x", uint8(2))

	f.Fuzz(func(t *testing.T, prevRaw, nextRaw string, hops uint8) {
		prev, err := url.Parse(prevRaw)
		if err != nil {
			t.Skip()
		}
		next, err := url.Parse(nextRaw)
		if err != nil {
			t.Skip()
		}
		via := make([]*http.Request, 1+int(hops)%8)
		for i := range via {
			via[i] = &http.Request{URL: prev}
		}
		if err := redirect.Check(&http.Request{URL: next}, via); err != nil {
			return
		}
		switch {
		case len(via) >= 5:
			t.Fatalf("followed a redirect after %d hops", len(via))
		case next.Scheme != "https":
			t.Fatalf("followed a redirect to %q", nextRaw)
		case fuzzPrivate(next.Hostname()):
			t.Fatalf("followed a redirect to the internal address %q", nextRaw)
		case prev.Scheme != next.Scheme || !strings.EqualFold(prev.Hostname(), next.Hostname()) || fuzzPort(prev) != fuzzPort(next):
			t.Fatalf("followed a cross-origin redirect from %q to %q", prevRaw, nextRaw)
		}
	})
}
