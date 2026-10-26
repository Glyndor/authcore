package responses_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// An endless body must be cut at the cap: the client may not keep reading.
func TestHostile_Response_endlessBodyIsCutAtTheCap(t *testing.T) {
	for _, s := range surfaces() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			var written atomic.Int64
			srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"pad":"`))
				chunk := bytes.Repeat([]byte("a"), 64<<10)
				for r.Context().Err() == nil && written.Load() < 256<<20 {
					n, err := w.Write(chunk)
					written.Add(int64(n))
					if err != nil {
						return
					}
				}
			}))
			start := time.Now()
			err := s.call(t, srv.URL, &http.Client{Timeout: 5 * time.Second})
			if err == nil {
				t.Fatal("an endless body was accepted")
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("took %v to give up on an endless body", elapsed)
			}
			// The cap is 1 MiB; the rest is whatever the socket buffers swallowed.
			time.Sleep(50 * time.Millisecond)
			if w := written.Load(); w > 24<<20 {
				t.Fatalf("the server wrote %d MiB before the client stopped reading", w>>20)
			}
		})
	}
}

// drain reads the request body so the server notices when the client hangs up
// (net/http only watches the connection once the body has been consumed).
func drain(r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }

// A server that answers one byte at a time must not hold the client past its timeout.
func TestHostile_Response_slowlorisIsBoundedByTheClientTimeout(t *testing.T) {
	modes := map[string]func(w http.ResponseWriter, r *http.Request){
		"silence after the request": func(_ http.ResponseWriter, r *http.Request) { drain(r); <-r.Context().Done() },
		"headers then silence": func(w http.ResponseWriter, r *http.Request) {
			drain(r)
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		},
		"a byte every 20 ms": func(w http.ResponseWriter, r *http.Request) {
			drain(r)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pad":"`))
			for r.Context().Err() == nil {
				if _, err := w.Write([]byte("a")); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
			}
		},
	}
	for _, s := range surfaces() {
		for name, h := range modes {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				srv := hostiletest.Serve(t, http.HandlerFunc(h))
				start := time.Now()
				err := s.call(t, srv.URL, &http.Client{Timeout: 300 * time.Millisecond})
				if err == nil {
					t.Fatal("a stalled answer was accepted")
				}
				if elapsed := time.Since(start); elapsed > 3*time.Second {
					t.Fatalf("a 300 ms client timeout held for %v", elapsed)
				}
			})
		}
	}
}

// The caller's context is honoured as well, with no client timeout involved.
func TestHostile_Response_callerContextCutsAStalledFetch(t *testing.T) {
	srv := hostiletest.Serve(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { drain(r); <-r.Context().Done() }))
	for _, s := range surfaces() {
		t.Run(s.name, func(t *testing.T) {
			// surfaces use ctx(t); rebuild the call with a short context here.
			c, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			var err error
			switch s.name {
			case "exchange":
				_, err = hostiletest.TokenClient(t, srv.URL+"/token", nil).Exchange(c, "code", "verifier")
			case "userinfo":
				_, err = hostiletest.UserinfoClient(t, srv.URL, nil).UserInfo(c, "tok")
			case "jwks":
				_, err = hostiletest.OIDCClient(t, srv.URL, nil).VerifyIDToken(c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
			case "discovery":
				_, err = oauth.Discover(c, srv.URL, nil)
			}
			if err == nil {
				t.Fatal("a stalled fetch returned success")
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("a 150 ms context held for %v", elapsed)
			}
		})
	}
}

// A caller-supplied client with no timeout must not remove the bound: the
// library puts its own back. Observed through the deadline the transport sees.
type deadlineProbe struct {
	remaining atomic.Int64 // nanoseconds; -1 when the request had no deadline
}

func (d *deadlineProbe) RoundTrip(r *http.Request) (*http.Response, error) {
	if dl, ok := r.Context().Deadline(); ok {
		d.remaining.Store(int64(time.Until(dl)))
	} else {
		d.remaining.Store(-1)
	}
	return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

func TestHostile_Response_clientWithoutTimeoutGetsTheLibraryBound(t *testing.T) {
	for _, s := range surfaces() {
		t.Run(s.name, func(t *testing.T) {
			probe := &deadlineProbe{}
			// ctx(t) carries an 8 s deadline of its own; the probe must see the client bound instead.
			_ = runWithoutContextDeadline(t, s, &http.Client{Transport: probe})
			got := time.Duration(probe.remaining.Load())
			if got <= 0 || got > 10*time.Second || got < 5*time.Second {
				t.Fatalf("a client with Timeout 0 left the request with deadline %v, want about 10s", got)
			}
		})
	}
	t.Run("a tighter caller timeout is kept", func(t *testing.T) {
		probe := &deadlineProbe{}
		_ = runWithoutContextDeadline(t, surfaces()[0], &http.Client{Transport: probe, Timeout: 700 * time.Millisecond})
		if got := time.Duration(probe.remaining.Load()); got <= 0 || got > 700*time.Millisecond {
			t.Fatalf("the caller's 700 ms timeout was replaced: deadline %v", got)
		}
	})
}

func runWithoutContextDeadline(t *testing.T, s surface, hc *http.Client) error {
	t.Helper()
	bg := context.Background()
	const base = "https://idp.example"
	switch s.name {
	case "exchange":
		c := hostiletest.TokenClient(t, base+"/token", func(c *oauth.Config) { c.HTTPClient = hc })
		_, err := c.Exchange(bg, "code", "verifier")
		return err
	case "userinfo":
		c := hostiletest.UserinfoClient(t, base+"/userinfo", func(c *oauth.Config) { c.HTTPClient = hc })
		_, err := c.UserInfo(bg, "tok")
		return err
	case "jwks":
		c := hostiletest.OIDCClient(t, base+"/jwks", func(c *oauth.Config) { c.HTTPClient = hc })
		_, err := c.VerifyIDToken(bg, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
		return err
	default:
		_, err := oauth.Discover(bg, base, hc)
		return err
	}
}

// The connection dies in the middle of an answer that promised more.
func TestHostile_Response_connectionDroppedMidBody(t *testing.T) {
	for _, s := range surfaces() {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			var base string
			srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				good := s.good(t, base)
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
				_, _ = buf.Write(good) // a complete, valid document, but fewer bytes than promised
				_ = buf.Flush()
			}))
			base = srv.URL
			if err := s.call(t, base, nil); err == nil {
				t.Fatal("an answer cut short of its Content-Length was accepted")
			}
		})
	}
}
