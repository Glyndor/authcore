package netguard_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
)

type legacyConn struct {
	closed  atomic.Bool
	written atomic.Int32
	remote  net.Addr
}

func (*legacyConn) Read([]byte) (int, error)      { return 0, io.EOF }
func (c *legacyConn) Write(p []byte) (int, error) { c.written.Add(int32(len(p))); return len(p), nil }
func (c *legacyConn) Close() error                { c.closed.Store(true); return nil }
func (*legacyConn) LocalAddr() net.Addr           { return &net.TCPAddr{} }
func (c *legacyConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 443}
}
func (*legacyConn) SetDeadline(time.Time) error      { return nil }
func (*legacyConn) SetReadDeadline(time.Time) error  { return nil }
func (*legacyConn) SetWriteDeadline(time.Time) error { return nil }

func TestLegacyTransportEnforcesDestinationPolicy(t *testing.T) {
	for _, mode := range []string{"Dial", "DialContext", "DialTLS", "DialTLSContext", "DialAndDialTLS"} {
		t.Run(mode, func(t *testing.T) {
			conn := &legacyConn{}
			legacy := func(string, string) (net.Conn, error) { return conn, nil }
			modern := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			unused := func(string, string) (net.Conn, error) {
				t.Error("inactive legacy hook was called")
				return nil, errors.New("inactive hook")
			}
			original := &http.Transport{}
			scheme := "https"
			switch mode {
			case "Dial":
				scheme = "http"
				original.Dial = legacy //nolint:staticcheck // Legacy transport compatibility.
			case "DialContext":
				scheme = "http"
				original.DialContext = modern
				original.Dial = unused //nolint:staticcheck // Legacy transport compatibility.
			case "DialTLS":
				original.DialTLS = legacy //nolint:staticcheck // Legacy transport compatibility.
			case "DialTLSContext":
				original.DialTLSContext = modern
				original.DialTLS = unused //nolint:staticcheck // Legacy transport compatibility.
			case "DialAndDialTLS":
				original.Dial = unused    //nolint:staticcheck // Legacy transport compatibility.
				original.DialTLS = legacy //nolint:staticcheck // Legacy transport compatibility.
			}
			guarded := netguard.Guard(original).(*http.Transport)
			defer guarded.CloseIdleConnections()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, scheme+"://keys.example/jwks", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := guarded.RoundTrip(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, netguard.ErrInternalAddress) {
				t.Errorf("request error = %v, want internal-address refusal", err)
			}
			if !conn.closed.Load() || conn.written.Load() != 0 {
				t.Errorf("refused connection: closed=%v, written=%d", conn.closed.Load(), conn.written.Load())
			}
			if guarded == original {
				t.Error("caller transport was not cloned")
			}
		})
	}
}

func TestLegacyTransportPreservesAllowedDialing(t *testing.T) {
	for _, mode := range []string{"Dial", "DialTLS"} {
		t.Run(mode, func(t *testing.T) {
			conn := &legacyConn{remote: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443}}
			legacy := func(string, string) (net.Conn, error) { return conn, nil }
			original := &http.Transport{}
			if mode == "Dial" {
				original.Dial = legacy //nolint:staticcheck // Legacy transport compatibility.
			} else {
				original.DialTLS = legacy //nolint:staticcheck // Legacy transport compatibility.
			}
			guarded := netguard.Guard(original).(*http.Transport)
			defer guarded.CloseIdleConnections()
			dial := guarded.Dial //nolint:staticcheck // Legacy transport compatibility.
			if mode == "DialTLS" {
				dial = guarded.DialTLS //nolint:staticcheck // Legacy transport compatibility.
			} else if guarded.DialContext != nil {
				t.Fatal("legacy-only dialing gained a higher-precedence hook")
			}
			got, err := dial("tcp", "keys.example:443")
			if err != nil || got != conn || conn.closed.Load() {
				t.Fatalf("public connection = %v, %v, closed=%v", got, err, conn.closed.Load())
			}
			conn.remote = nil
			dial = original.Dial //nolint:staticcheck // Legacy transport compatibility.
			if mode == "DialTLS" {
				dial = original.DialTLS //nolint:staticcheck // Legacy transport compatibility.
			}
			got, err = dial("tcp", "keys.example:443")
			if err != nil || got != conn || conn.closed.Load() {
				t.Errorf("caller hook changed: connection=%v, err=%v, closed=%v", got, err, conn.closed.Load())
			}
		})
	}
}
