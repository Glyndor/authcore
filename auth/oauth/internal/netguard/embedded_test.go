package netguard_test

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
)

// An IPv6 address that embeds an IPv4 one (NAT64, 6to4) must be judged exactly
// as the embedded IPv4 address is judged on its own. Each sample is chosen so
// that reading one embedded byte from the wrong position flips the verdict.
func TestEmbeddedIPv4IsJudgedLikeThePlainAddress(t *testing.T) {
	t.Parallel()
	samples := []string{
		"10.1.2.3", "172.16.0.1", "172.0.0.1", "172.15.9.9", "172.32.0.1",
		"192.0.0.200", "192.0.5.5", "192.0.1.1", "198.18.0.1", "198.20.0.1",
		"100.64.0.1", "100.128.0.1", "169.254.1.2", "169.253.1.2",
		"0.0.0.0", "0.0.0.1", "127.0.0.1", "8.8.8.8", "240.0.0.1",
	}
	for _, s := range samples {
		v4 := netip.MustParseAddr(s).As4()
		nat64 := [16]byte{0x00, 0x64, 0xff, 0x9b}
		copy(nat64[12:], v4[:])
		sixToFour := [16]byte{0x20, 0x02}
		copy(sixToFour[2:6], v4[:])
		want := netguard.InternalAddr(netip.MustParseAddr(s))
		for name, raw := range map[string][16]byte{"nat64": nat64, "6to4": sixToFour} {
			got := netguard.InternalAddr(netip.AddrFrom16(raw))
			if got != want {
				t.Errorf("%s form of %s: internal=%v, the plain address says %v", name, s, got, want)
			}
		}
	}
}

// The default transport carries the standard library's defaults plus the
// dial-time check, and nothing narrower.
func TestDefaultTransportKeepsTheStandardDefaults(t *testing.T) {
	t.Parallel()
	got, ok := netguard.DefaultTransport().(*http.Transport)
	if !ok {
		t.Fatalf("DefaultTransport is %T, want *http.Transport", netguard.DefaultTransport())
	}
	std := http.DefaultTransport.(*http.Transport)
	if got.ForceAttemptHTTP2 != std.ForceAttemptHTTP2 {
		t.Errorf("ForceAttemptHTTP2 = %v, want %v", got.ForceAttemptHTTP2, std.ForceAttemptHTTP2)
	}
	if got.MaxIdleConns != std.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", got.MaxIdleConns, std.MaxIdleConns)
	}
	if got.IdleConnTimeout != std.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", got.IdleConnTimeout, std.IdleConnTimeout)
	}
	if got.TLSHandshakeTimeout != std.TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", got.TLSHandshakeTimeout, std.TLSHandshakeTimeout)
	}
	if got.ExpectContinueTimeout != std.ExpectContinueTimeout {
		t.Errorf("ExpectContinueTimeout = %v, want %v", got.ExpectContinueTimeout, std.ExpectContinueTimeout)
	}
}
