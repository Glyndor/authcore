package netguard

import (
	"net/netip"
	"testing"
)

func TestInternalAddr(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "127.5.5.5": true, "::1": true,
		"10.0.0.5": true, "172.16.0.1": true, "192.168.1.1": true, "fd00::1": true, "fc00::1": true,
		"169.254.169.254": true, "fe80::1": true, "fe80::1%eth0": true,
		"0.0.0.0": true, "::": true, "224.0.0.1": true, "ff02::1": true, "ff01::1": true,
		"100.64.0.1": true, "100.100.100.200": true, "198.18.0.1": true, "192.0.0.1": true, "240.0.0.1": true,
		"::ffff:10.0.0.5": true, "::ffff:127.0.0.1": true, "::127.0.0.1": true,
		"64:ff9b::a00:5": true, "64:ff9b::808:808": false,
		"2002:a00:5::1": true, "2002:808:808::1": false,
		"100::1":  true,
		"8.8.8.8": false, "1.1.1.1": false, "93.184.216.34": false,
		"2606:4700:4700::1111": false, "::ffff:8.8.8.8": false,
	} {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			t.Fatalf("test bug: %q: %v", addr, err)
		}
		if got := InternalAddr(a); got != want {
			t.Errorf("InternalAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestInternalHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"169.254.169.254": true, "10.0.0.5": true, "[fd00::1]": true, "::1": true,
		"localhost": true, "LOCALHOST": true, "localhost.": true, "api.localhost": true,
		"metadata.google.internal": true, "Metadata.Google.Internal.": true, "metadata": true, "instance-data": true,
		"example.com": false, "8.8.8.8": false, "localhost.evil.com": false, "": false,
	} {
		if got := InternalHost(host); got != want {
			t.Errorf("InternalHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLoopback(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "127.0.0.2": true, "::1": true, "[::1]": true, "::ffff:127.0.0.1": true,
		"LOCALHOST": false, "localhost.": false, "10.0.0.1": false, "example.com": false, "": false,
	} {
		if got := Loopback(host); got != want {
			t.Errorf("Loopback(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestLiteral(t *testing.T) {
	t.Parallel()
	if _, ok := Literal("example.com"); ok {
		t.Error("a name is not a literal")
	}
	if _, ok := Literal("2130706433"); ok {
		t.Error("a decimal integer is not a literal for this check; the dial check handles it")
	}
	if a, ok := Literal("[::1]"); !ok || a != netip.MustParseAddr("::1") {
		t.Errorf("Literal([::1]) = %v, %v", a, ok)
	}
}
