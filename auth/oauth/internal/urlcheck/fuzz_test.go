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

// fuzzLoopback reports whether host is a loopback destination, written from
// the address classes alone: a loopback literal, or the name localhost in the
// exact spelling the library uses.
func fuzzLoopback(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.WithZone("").Unmap().IsLoopback()
	}
	return host == "localhost"
}

// fuzzInternal reports whether host is a destination inside the machine or
// inside the private network: an address in one of the ranges that never
// carry a public provider, or a name that always points inside.
//
// It is written from the address classes and the DNS rules, not from the
// package under test, and it is deliberately narrower than the package's own
// set: everything this function calls internal is internal for the library
// too, so a refusal of such a host is certainly required, while the converse
// is a claim this oracle cannot make.
func fuzzInternal(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.WithZone("").Unmap()
		return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
			a.IsMulticast() || a.IsUnspecified()
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	switch name {
	case "localhost", "metadata", "metadata.google.internal", "instance-data":
		return true
	}
	return strings.HasSuffix(name, ".localhost")
}

// fuzzIsLiteral reports whether host is an IP address rather than a name.
func fuzzIsLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// FuzzRequireExternal puts arbitrary URLs through the internal-destination
// check. An internal destination is always refused; the loopback is the one
// exception, and only when the caller asked for it; and a name that is not
// internal is always accepted, because the set of names that point inside is
// exactly the one this oracle lists.
//
// The literal case is checked in one direction only: this oracle knows a
// narrower set of internal ranges than the library does, so it can demand a
// refusal but cannot demand an acceptance.
func FuzzRequireExternal(f *testing.F) {
	for _, seed := range []string{
		"https://idp.example/token", "https://8.8.8.8/token", "https://[2606:4700:4700::1111]/t",
		"https://127.0.0.1/token", "https://127.0.0.2/token", "https://[::1]/token", "https://[::ffff:127.0.0.1]/token",
		"http://localhost:8080/x", "https://localhost/token", "https://LOCALHOST/token", "https://localhost./token",
		"https://10.0.0.5/token", "https://172.16.0.1/token", "https://192.168.1.1/token", "https://[fd00::1]/token",
		"https://169.254.169.254/latest/meta-data", "https://[fe80::1%25eth0]/token",
		"https://0.0.0.0/token", "https://[::]/token", "https://224.0.0.1/token",
		"https://metadata.google.internal/token", "https://metadata/token", "https://instance-data/token",
		"https://api.localhost/token", "https://localhost.evil.example/token",
		"https://100.64.0.1/token", "https://[64:ff9b::a00:5]/token", "https:///token", "https://user:pw@127.0.0.1/token",
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Add("", false)
	f.Add("", true)

	f.Fuzz(func(t *testing.T, raw string, allowLoopback bool) {
		u, perr := url.Parse(raw)
		if perr != nil || u == nil {
			// RequireExternal reports nothing for a string that does not
			// parse, because RequireHTTPS runs first and refuses it.
			return
		}
		host := u.Hostname()
		loopback := fuzzLoopback(host)
		internal := fuzzInternal(host)

		err := urlcheck.RequireExternal("url", raw, allowLoopback)

		if internal && (!allowLoopback || !loopback) {
			// An internal destination is refused, and the development
			// exception covers the loopback only.
			if err == nil {
				t.Fatalf("accepted %q, whose host %q is an internal destination", raw, host)
			}
			return
		}
		if loopback {
			// A loopback destination is accepted only when the caller asked
			// for it, and refused when it did not.
			if allowLoopback && err != nil {
				t.Fatalf("refused %q, whose host %q is a loopback the caller allowed", raw, host)
			}
			if !allowLoopback && err == nil {
				t.Fatalf("accepted %q, whose host %q is a loopback the caller did not allow", raw, host)
			}
			return
		}
		if !fuzzIsLiteral(host) && err != nil {
			// A name that is not internal is an ordinary public host.
			t.Fatalf("refused %q, whose host %q is an ordinary public name", raw, host)
		}
	})
}
