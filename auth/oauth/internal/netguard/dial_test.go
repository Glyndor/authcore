package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestControl(t *testing.T) {
	t.Parallel()
	for addr, wantRefused := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:443": true, "10.0.0.5:443": true, "169.254.169.254:80": true,
		"[::ffff:192.168.0.1]:80": true, "8.8.8.8:443": false, "[2606:4700:4700::1111]:443": false,
		"not-an-ip:80": true,
	} {
		err := Control("tcp", addr, nil)
		if refused := errors.Is(err, ErrInternalAddress); refused != wantRefused {
			t.Errorf("Control(%q) = %v, want refused=%v", addr, err, wantRefused)
		}
	}
	if err := Control("tcp", "no-port", nil); err == nil {
		t.Error("an address without a port was accepted")
	}
}

func TestExplicit(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:80": true, "10.0.0.5:443": true, "localhost:8080": true, "localhost": true,
		"example.com:443": false, "api.localhost:443": false, "2130706433:80": false,
	} {
		if got := explicit(addr); got != want {
			t.Errorf("explicit(%q) = %v, want %v", addr, got, want)
		}
	}
}

// fakeConn reports a chosen remote address.
type fakeConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { c.closed = true; return nil }

func TestWrap(t *testing.T) {
	t.Parallel()
	g := &guard{}
	g.proxies.Store("proxy.corp:3128", struct{}{})
	dialTo := func(remote string, conn *fakeConn) dialFunc {
		return func(context.Context, string, string) (net.Conn, error) {
			conn.remote = &net.TCPAddr{IP: net.ParseIP(remote), Port: 443}
			return conn, nil
		}
	}
	for _, tc := range []struct {
		name, addr, remote string
		refused            bool
	}{
		{"name resolving inward", "example.com:443", "127.0.0.1", true},
		{"name resolving to metadata", "example.com:443", "169.254.169.254", true},
		{"name resolving outward", "example.com:443", "93.184.216.34", false},
		{"explicit literal is the URL check's", "10.0.0.5:443", "10.0.0.5", false},
		{"configured proxy", "proxy.corp:3128", "10.9.9.9", false},
	} {
		conn := &fakeConn{}
		got, err := g.wrap(dialTo(tc.remote, conn))(context.Background(), "tcp", tc.addr)
		if refused := errors.Is(err, ErrInternalAddress); refused != tc.refused {
			t.Errorf("%s: err = %v, want refused=%v", tc.name, err, tc.refused)
		}
		if tc.refused && (!conn.closed || got != nil) {
			t.Errorf("%s: the refused connection was not closed and dropped", tc.name)
		}
		if !tc.refused && (err != nil || got == nil) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A dial error passes through, and so does a connection whose remote
	// address is not an IP address (the operator's own unix socket or pipe).
	boom := errors.New("boom")
	if _, err := g.wrap(func(context.Context, string, string) (net.Conn, error) { return nil, boom })(context.Background(), "tcp", "example.com:443"); !errors.Is(err, boom) {
		t.Errorf("dial error = %v", err)
	}
	pipe := &fakeConn{remote: &net.UnixAddr{Name: "/run/idp.sock", Net: "unix"}}
	if _, err := g.wrap(func(context.Context, string, string) (net.Conn, error) { return pipe, nil })(context.Background(), "tcp", "example.com:443"); err != nil {
		t.Errorf("a unix socket was refused: %v", err)
	}
}

func TestProxyFuncRecordsTheProxy(t *testing.T) {
	t.Parallel()
	g := &guard{}
	for raw, addr := range map[string]string{
		"http://10.1.1.1:3128": "10.1.1.1:3128", "http://proxy.corp": "proxy.corp:80",
		"https://proxy.corp": "proxy.corp:443", "socks5://[fd00::9]": "[fd00::9]:1080",
	} {
		u, _ := url.Parse(raw)
		proxy := g.proxyFunc(func(*http.Request) (*url.URL, error) { return u, nil })
		if got, err := proxy(&http.Request{}); err != nil || got != u {
			t.Fatalf("proxyFunc(%s) = %v, %v", raw, got, err)
		}
		if !g.trusted(addr) {
			t.Errorf("%s: %s was not recorded", raw, addr)
		}
	}
	if g.trusted("other.corp:3128") {
		t.Error("an unrelated address is trusted")
	}
	none := g.proxyFunc(func(*http.Request) (*url.URL, error) { return nil, nil })
	if u, err := none(&http.Request{}); u != nil || err != nil {
		t.Errorf("no proxy: %v, %v", u, err)
	}
	failing := g.proxyFunc(func(*http.Request) (*url.URL, error) { return nil, errors.New("bad") })
	if _, err := failing(&http.Request{}); err == nil {
		t.Error("the proxy error was swallowed")
	}
}

func TestDialer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	g := &guard{}
	dial := g.dialer()
	// A literal is the URL checks' business and connects.
	conn, err := dial(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("literal loopback: %v", err)
	}
	_ = conn.Close()
	// localhost is the development exception.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	conn, err = dial(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("localhost: %v", err)
	}
	_ = conn.Close()
	// Any other name goes through Control; one that cannot resolve fails.
	if _, err := dial(context.Background(), "tcp", "name.invalid:443"); err == nil {
		t.Error("an unresolvable name connected")
	}
}

func TestGuard(t *testing.T) {
	t.Parallel()
	if Guard(nil) != DefaultTransport() {
		t.Error("nil did not become the default transport")
	}
	custom := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	if Guard(custom) == nil {
		t.Error("a custom RoundTripper was dropped")
	}

	dialed := false
	orig := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.5")}}, nil
		},
		Proxy: http.ProxyFromEnvironment,
	}
	got, ok := Guard(orig).(*http.Transport)
	if !ok || got == orig {
		t.Fatalf("Guard(*http.Transport) = %T, want a clone", got)
	}
	if _, err := got.DialContext(context.Background(), "tcp", "example.com:80"); !errors.Is(err, ErrInternalAddress) || !dialed {
		t.Errorf("DialContext = %v (dialed %v)", err, dialed)
	}
	if _, err := got.DialTLSContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrInternalAddress) {
		t.Errorf("DialTLSContext = %v", err)
	}
	if orig.DialContext == nil || got.Proxy == nil {
		t.Error("clone lost a field")
	}

	plain := Guard(&http.Transport{}).(*http.Transport)
	if plain.DialContext == nil {
		t.Error("a transport with no dialing got no guarded dialer")
	}

	legacy := &http.Transport{Dial: func(string, string) (net.Conn, error) { return nil, nil }} //nolint:staticcheck // Exercising the deprecated hook.
	if Guard(legacy) != http.RoundTripper(legacy) {
		t.Error("a transport with a legacy dial hook was replaced")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
