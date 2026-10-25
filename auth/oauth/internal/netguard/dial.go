package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"
)

// ErrInternalAddress is the refusal to connect to an internal address.
var ErrInternalAddress = errors.New("refusing to connect to an internal address")

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Control is a net.Dialer Control function that refuses a connection whose
// resolved address is internal. It runs once per candidate address, after name
// resolution and before the socket connects, so neither a name that resolves
// inward nor a second address a name gained after it was checked gets through.
func Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if a, ok := Literal(host); !ok || InternalAddr(a) {
		return ErrInternalAddress
	}
	return nil
}

// guard holds what a guarded transport needs to tell a connection to refuse
// from one the operator asked for.
type guard struct {
	// proxies are the host:port pairs a proxy function returned. They come
	// from the operator's own configuration (an environment variable, a
	// field), so connecting to one is allowed; the proxy resolves the target.
	proxies sync.Map
}

// explicit reports whether addr names its host as an IP literal or localhost.
// Those are judged by the URL checks, which know whether the operator typed
// them; the dial check is for names that only resolve to an internal address.
func explicit(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if _, ok := Literal(host); ok {
		return true
	}
	return Loopback(host)
}

func (g *guard) trusted(addr string) bool {
	if explicit(addr) {
		return true
	}
	_, isProxy := g.proxies.Load(addr)
	return isProxy
}

// dialer returns the dial function of a transport with no custom dialing: the
// standard library defaults, plus Control for every name that is not a
// literal.
func (g *guard) dialer() dialFunc {
	plain := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	checked := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: Control}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if g.trusted(addr) {
			return plain.DialContext(ctx, network, addr)
		}
		return checked.DialContext(ctx, network, addr)
	}
}

// wrap checks the connection another dial function returns. It is the only
// hook available over a dialer the library does not own: the check happens
// after the connection exists but before any request bytes are written to it.
// A remote address that is not an IP address (a unix socket, an in-memory
// pipe) is the operator's own dialing and is left alone.
func (g *guard) wrap(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil || g.trusted(addr) {
			return conn, err
		}
		if ap, perr := netip.ParseAddrPort(conn.RemoteAddr().String()); perr == nil && InternalAddr(ap.Addr()) {
			_ = conn.Close()
			return nil, ErrInternalAddress
		}
		return conn, nil
	}
}

// proxyFunc records the proxy a request will dial before handing it back.
func (g *guard) proxyFunc(orig func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		u, err := orig(r)
		if err == nil && u != nil {
			g.proxies.Store(proxyAddr(u), struct{}{})
		}
		return u, err
	}
}

// proxyAddr is the host:port the transport dials for proxy u.
func proxyAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
