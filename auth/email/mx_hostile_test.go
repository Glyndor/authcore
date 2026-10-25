package email

// Hostile DNS answers for VerifyDomain. These live in the package, not under
// tests/hostile, because the resolver is not part of the public API: the stub
// has to replace the unexported verifier. Nothing here touches the network.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email/internal/mx"
)

// stubResolver answers from a function and records every name it was asked.
type stubResolver struct {
	mu    sync.Mutex
	calls []string
	fn    func(ctx context.Context, name string) ([]*net.MX, error)
}

func (s *stubResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
	return s.fn(ctx, name)
}

func (s *stubResolver) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func newHostileEmail(t *testing.T, fn func(ctx context.Context, name string) ([]*net.MX, error)) (*Email, *stubResolver) {
	t.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(auth)
	if err != nil {
		t.Fatal(err)
	}
	r := &stubResolver{fn: fn}
	e.mx = mx.New(r, time.Minute)
	return e, r
}

func hasMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mail.example.net.", Pref: 10}}, nil
}

// What the resolver says is classified once and the classes stay apart: a real
// answer, no answer, a null MX, a missing domain and a broken resolver are five
// different outcomes, and the broken one is never read as "no MX".
func TestHostile_MX_answersAreClassifiedAndKeptApart(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}
	cases := map[string]struct {
		answer []*net.MX
		err    error
		want   error // nil means the domain verifies
	}{
		"real record":        {answer: []*net.MX{{Host: "mx.example.net.", Pref: 1}}},
		"many records":       {answer: manyMX(10000)},
		"no records":         {answer: nil, want: ErrDomainNoMX},
		"empty slice":        {answer: []*net.MX{}, want: ErrDomainNoMX},
		"null MX":            {answer: []*net.MX{{Host: ".", Pref: 0}}, want: ErrDomainNoMX},
		"null MX empty host": {answer: []*net.MX{{Host: "", Pref: 0}}, want: ErrDomainNoMX},
		"nil record":         {answer: []*net.MX{{}}, want: ErrDomainNoMX},
		"not found":          {err: notFound, want: ErrDomainNoMX},
		"timeout":            {err: timeout, want: ErrDomainUnresolvable},
		"server failure":     {err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}, want: ErrDomainUnresolvable},
		"plain error":        {err: errors.New("connection refused"), want: ErrDomainUnresolvable},
		"wrapped not found":  {err: fmt.Errorf("lookup: %w", notFound), want: ErrDomainNoMX},
		"records and error":  {answer: []*net.MX{{Host: "mx.example.net.", Pref: 1}}, err: errors.New("partial"), want: ErrDomainUnresolvable},
		"cancelled resolver": {err: context.Canceled, want: ErrDomainUnresolvable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e, _ := newHostileEmail(t, func(context.Context, string) ([]*net.MX, error) { return tc.answer, tc.err })
			err := e.VerifyDomain(context.Background(), "user@"+strings.ReplaceAll(name, " ", "-")+".example")
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("VerifyDomain = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("VerifyDomain = %v, want %v", err, tc.want)
			}
			if tc.want == ErrDomainUnresolvable && errors.Is(err, ErrDomainNoMX) {
				t.Fatal("a resolver failure was reported as a domain with no MX")
			}
		})
	}
}

func manyMX(n int) []*net.MX {
	out := make([]*net.MX, n)
	for i := range out {
		out[i] = &net.MX{Host: fmt.Sprintf("mx%d.example.net.", i), Pref: uint16(i)}
	}
	return out
}

// Names that cannot be a DNS name never reach the resolver: an address with no
// domain, an empty domain, an empty label, a label over 63 bytes and a name
// over 253 bytes are refused first.
func TestHostile_MX_implausibleNamesNeverReachTheResolver(t *testing.T) {
	e, r := newHostileEmail(t, hasMX)
	label64 := strings.Repeat("a", 64)
	long := strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com"
	for name, addr := range map[string]struct {
		addr string
		want error
	}{
		"no at sign":    {"nodomain", ErrDomainNoMX},
		"empty":         {"", ErrDomainNoMX},
		"empty domain":  {"user@", ErrDomainNoMX},
		"empty label":   {"user@a..com", ErrInvalidEmail},
		"leading dot":   {"user@.com", ErrInvalidEmail},
		"trailing dot":  {"user@example.com.", ErrInvalidEmail},
		"label of 64":   {"user@" + label64 + ".com", ErrInvalidEmail},
		"name of 255":   {"user@" + long, ErrInvalidEmail},
		"only a dot":    {"user@.", ErrInvalidEmail},
		"10 MiB domain": {"user@" + strings.Repeat("a", 10<<20), ErrInvalidEmail},
	} {
		start := time.Now()
		if err := e.VerifyDomain(context.Background(), addr.addr); !errors.Is(err, addr.want) {
			t.Errorf("%s: VerifyDomain = %v, want %v", name, err, addr.want)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
	if n := r.count(); n != 0 {
		t.Fatalf("the resolver was asked %d times for names that cannot be looked up: %q", n, r.calls)
	}
}

// A resolver that never answers cannot hold a caller past its own deadline,
// and many callers asking about one domain share a single lookup.
func TestHostile_MX_stalledResolverIsBoundedByTheCallersContextAndCoalesced(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	e, r := newHostileEmail(t, func(ctx context.Context, name string) ([]*net.MX, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return hasMX(ctx, name)
	})

	const callers = 50
	var wg sync.WaitGroup
	var timedOut atomic.Int64
	start := time.Now()
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := e.VerifyDomain(ctx, "user@slow.example"); errors.Is(err, context.DeadlineExceeded) {
				timedOut.Add(1)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("callers were held for %v by a resolver that never answers", d)
	}
	if timedOut.Load() != callers {
		t.Fatalf("%d of %d callers got the deadline error", timedOut.Load(), callers)
	}
	if n := r.count(); n != 1 {
		t.Fatalf("the resolver was asked %d times for one domain, want 1", n)
	}
}

// A caller that gives up does not poison the answer for the next one: when the
// lookup finishes, a caller with a live context gets the real result.
func TestHostile_MX_abandonedLookupStillAnswersTheNextCaller(t *testing.T) {
	release := make(chan struct{})
	e, r := newHostileEmail(t, func(ctx context.Context, name string) ([]*net.MX, error) {
		<-release
		return hasMX(ctx, name)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := e.VerifyDomain(ctx, "user@later.example"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first caller: %v, want a deadline error", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := e.VerifyDomain(context.Background(), "user@later.example")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("second caller never got the answer: %v", err)
		}
	}
	if n := r.count(); n != 1 {
		t.Fatalf("the resolver was asked %d times, want 1", n)
	}
}

// A failure is remembered briefly and a confirmed answer for the full TTL, so a
// flapping resolver cannot be turned into a flood, and a cached failure is
// reported as a failure, not as "no MX".
func TestHostile_MX_answersAreCachedAndFailuresStayFailures(t *testing.T) {
	var mode atomic.Int64 // 0 = broken, 1 = healthy
	e, r := newHostileEmail(t, func(ctx context.Context, name string) ([]*net.MX, error) {
		if mode.Load() == 0 {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
		return hasMX(ctx, name)
	})
	for i := 0; i < 20; i++ {
		if err := e.VerifyDomain(context.Background(), "user@flap.example"); !errors.Is(err, ErrDomainUnresolvable) || errors.Is(err, ErrDomainNoMX) {
			t.Fatalf("call %d: %v, want ErrDomainUnresolvable", i, err)
		}
	}
	if n := r.count(); n != 1 {
		t.Fatalf("a broken resolver was asked %d times for 20 calls, want 1", n)
	}

	mode.Store(1)
	e2, r2 := newHostileEmail(t, hasMX)
	for i := 0; i < 20; i++ {
		if err := e2.VerifyDomain(context.Background(), "user@good.example"); err != nil {
			t.Fatal(err)
		}
	}
	if n := r2.count(); n != 1 {
		t.Fatalf("a healthy domain was looked up %d times for 20 calls, want 1", n)
	}
}

// Filling the cache with distinct domains is bounded, and domains that did not
// fit are simply looked up each time instead of growing memory.
func TestHostile_MX_cacheIsBoundedAgainstDistinctDomains(t *testing.T) {
	e, r := newHostileEmail(t, hasMX)
	const distinct = 10500 // the cache holds 10,000 entries
	for i := 0; i < distinct; i++ {
		if err := e.VerifyDomain(context.Background(), fmt.Sprintf("u@d%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	before := r.count()
	if before != distinct {
		t.Fatalf("%d lookups for %d distinct domains", before, distinct)
	}
	// An early domain is still served from the cache; a late one that did not
	// fit is looked up again. Neither answer changes.
	if err := e.VerifyDomain(context.Background(), "u@d0.example"); err != nil {
		t.Fatal(err)
	}
	if r.count() != before {
		t.Error("a cached domain was looked up again")
	}
	if err := e.VerifyDomain(context.Background(), fmt.Sprintf("u@d%d.example", distinct-1)); err != nil {
		t.Fatal(err)
	}
	if r.count() != before+1 {
		t.Error("a domain beyond the cache bound was not looked up again")
	}
}

// Many goroutines over overlapping domains: no race, and every answer is the
// one the resolver gave for that domain.
func TestHostile_MX_concurrentUseIsRaceFree(t *testing.T) {
	e, _ := newHostileEmail(t, func(ctx context.Context, name string) ([]*net.MX, error) {
		if strings.HasPrefix(name, "bad") {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		return hasMX(ctx, name)
	})
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				good := fmt.Sprintf("u@ok%d.example", i%40)
				bad := fmt.Sprintf("u@bad%d.example", i%40)
				if err := e.VerifyDomain(context.Background(), good); err != nil {
					t.Errorf("%s: %v", good, err)
				}
				if err := e.VerifyDomain(context.Background(), bad); !errors.Is(err, ErrDomainNoMX) {
					t.Errorf("%s: %v", bad, err)
				}
			}
		}()
	}
	wg.Wait()
}
