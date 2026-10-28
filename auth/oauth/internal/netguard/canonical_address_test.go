package netguard_test

import (
	"net/netip"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
)

func TestInternalAddrJudgesMappedAndZonedRangesByTheirAddress(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]bool{
		"::ffff:0.1.2.3":            true,
		"::ffff:100.64.0.1":         true,
		"::ffff:198.18.0.1":         true,
		"::ffff:240.1.2.3":          true,
		"fec0::1%eth0":              true,
		"100::1%eth0":               true,
		"64:ff9b:1::1%eth0":         true,
		"64:ff9b::a00:1%eth0":       true,
		"2002:a00:1::1%eth0":        true,
		"::ffff:100.63.255.255":     false,
		"::ffff:198.17.255.255":     false,
		"2001:4860:4860::8888%eth0": false,
	} {
		t.Run(raw, func(t *testing.T) {
			if got := netguard.InternalAddr(netip.MustParseAddr(raw)); got != want {
				t.Fatalf("InternalAddr(%s) = %v, want %v", raw, got, want)
			}
		})
	}
}

func TestInternalAddrRefusesMulticastOutsideTheLocalScopes(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"239.1.2.3", "ff0e::1", "ff05::1", "::ffff:239.1.2.3"} {
		if !netguard.InternalAddr(netip.MustParseAddr(raw)) {
			t.Errorf("multicast destination %s was classified as public", raw)
		}
	}
	for _, raw := range []string{"223.255.255.255", "2001:4860:4860::8888"} {
		if netguard.InternalAddr(netip.MustParseAddr(raw)) {
			t.Errorf("public destination %s was classified as internal", raw)
		}
	}
}
