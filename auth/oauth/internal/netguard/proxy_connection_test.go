package netguard_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
)

type proxyConnection struct {
	net.Conn
	closed bool
}

func (*proxyConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 9, 9, 9), Port: 3128}
}
func (c *proxyConnection) Close() error { c.closed = true; return nil }

func TestGuardTrustsOnlyTheProxyReturnedByItsConfiguredProxyFunction(t *testing.T) {
	t.Parallel()
	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example:3128"}
	var dialed *proxyConnection
	original := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = &proxyConnection{}
			return dialed, nil
		},
	}
	guarded, ok := netguard.Guard(original).(*http.Transport)
	if !ok || guarded == original {
		t.Fatal("Guard did not return an independent transport")
	}
	proxy, err := guarded.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "provider.example"}})
	if err != nil || proxy != proxyURL {
		t.Fatalf("configured proxy changed: %v, %v", proxy, err)
	}
	conn, err := guarded.DialContext(context.Background(), "tcp", "proxy.example:3128")
	if err != nil || conn != dialed || dialed.closed {
		t.Fatalf("configured private proxy refused: conn=%v, err=%v", conn, err)
	}
	_ = conn.Close()
	conn, err = guarded.DialContext(context.Background(), "tcp", "other.example:3128")
	if conn != nil || !errors.Is(err, netguard.ErrInternalAddress) || !dialed.closed {
		t.Fatalf("unconfigured private destination escaped policy: conn=%v, err=%v, closed=%v", conn, err, dialed.closed)
	}
}
