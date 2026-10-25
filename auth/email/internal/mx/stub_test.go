package mx

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/mx/internal/cache"
)

// stubResolver satisfies Resolver with deterministic, in-process behaviour.
// The release channel lets a test hold a LookupMX call open until it has
// verified the ordering of concurrent callers; the started channel signals
// when the first call has reached the resolver.
type stubResolver struct {
	mu          sync.Mutex
	callCount   int
	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
	mx          []*net.MX
	err         error
}

func (s *stubResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	s.mu.Lock()
	s.callCount++
	s.mu.Unlock()
	s.startedOnce.Do(func() { close(s.started) })
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.mx, s.err
}

func (s *stubResolver) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}

// newStub returns a stub whose LookupMX returns immediately. Tests that
// need to hold a call open call withBlockingStub instead.
func newStub(mx []*net.MX, err error) *stubResolver {
	return &stubResolver{
		started: make(chan struct{}),
		mx:      mx,
		err:     err,
	}
}

// withBlockingStub returns a stub whose first LookupMX blocks until release
// is closed or the caller's context is cancelled. The started channel is
// closed when the call reaches LookupMX so the test can wait until the
// in-flight lookup is positioned before issuing the second call.
func withBlockingStub(mx []*net.MX, err error) *stubResolver {
	return &stubResolver{
		started: make(chan struct{}),
		release: make(chan struct{}),
		mx:      mx,
		err:     err,
	}
}

// newVerifier returns a Verifier on the default resolver and the default
// five-minute TTL; tests that need DNS control replace its resolver.
func newVerifier() *Verifier { return New(net.DefaultResolver, 5*time.Minute) }

// primeCache directly writes a cache entry, bypassing DNS, so we can test
// cache hit behaviour without network access.
func primeCache(m *Verifier, domain string, hasMX bool, ttl time.Duration) {
	m.cache.Store(domain, cache.Entry{HasMX: hasMX, ExpiresAt: time.Now().Add(ttl)})
}
