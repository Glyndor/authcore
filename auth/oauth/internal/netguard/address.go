// Package netguard decides which network destinations the OAuth client may reach and enforces it when
// connecting.
package netguard

import (
	"net/netip"
	"strings"
)

// internalPrefixes are ranges that net/netip does not classify as private or
// loopback but that never hold a public provider: carrier-grade NAT (where
// some clouds put their metadata service), the IETF protocol and benchmarking
// blocks, the reserved class E block, and the IPv6 forms that embed an IPv4
// address, which are checked through the embedded address.
var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("100::/64"),
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// internalNames are host names that always point inside, whatever the
// resolver says. The dial-time check catches the rest.
var internalNames = map[string]bool{
	"localhost":                true,
	"metadata":                 true,
	"metadata.google.internal": true,
	"instance-data":            true,
}

// InternalAddr reports whether a is loopback, private, link-local, multicast,
// unspecified or in one of the other ranges a public provider never uses.
func InternalAddr(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	if embedded, ok := embeddedV4(a); ok {
		return InternalAddr(embedded)
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range internalPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// embeddedV4 extracts the IPv4 address a NAT64 (64:ff9b::/96) or 6to4
// (2002::/16) IPv6 address carries.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// Literal parses host as an IP literal, with or without an IPv6 zone.
func Literal(host string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return a, err == nil
}

// Loopback reports whether host is a loopback literal or the name localhost,
// spelled in lower case: the development exception the library has always
// made, and no wider.
func Loopback(host string) bool {
	if a, ok := Literal(host); ok {
		return a.WithZone("").Unmap().IsLoopback()
	}
	return host == "localhost"
}

// InternalHost reports whether host, as written in a URL, is an internal
// destination: an internal IP literal or a name that always points inside.
// A name that merely resolves to an internal address is not seen here; the
// dial-time check handles it.
func InternalHost(host string) bool {
	if a, ok := Literal(host); ok {
		return InternalAddr(a)
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	return internalNames[name] || strings.HasSuffix(name, ".localhost")
}
