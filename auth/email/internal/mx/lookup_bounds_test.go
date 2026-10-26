package mx

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// deadlineProbe records the time left on the context LookupMX receives.
type deadlineProbe struct{ left time.Duration }

func (p *deadlineProbe) LookupMX(ctx context.Context, _ string) ([]*net.MX, error) {
	if d, ok := ctx.Deadline(); ok {
		p.left = time.Until(d)
	}
	return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
}

// The shared lookup runs under the module's own ten-second bound.
func TestVerifyBoundsTheSharedLookupToTenSeconds(t *testing.T) {
	t.Parallel()
	probe := &deadlineProbe{}
	if err := New(probe, time.Minute).Verify(context.Background(), "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if probe.left <= 9*time.Second || probe.left > 10*time.Second {
		t.Fatalf("lookup deadline is %v away, want just under 10s", probe.left)
	}
}

// A transport failure is remembered for thirty seconds, no more and no less:
// long enough to spare the resolver a retry storm, short enough to recover.
func TestVerifyRemembersAFailedLookupForThirtySeconds(t *testing.T) {
	t.Parallel()
	v := New(newStub(nil, errors.New("server failure")), time.Hour)
	_ = v.Verify(context.Background(), "user@example.com")
	entry, ok := v.cache.Cached("example.com")
	if !ok || !entry.DNSFailure {
		t.Fatalf("a failed lookup must be cached as a DNS failure, got %+v ok=%v", entry, ok)
	}
	if left := time.Until(entry.ExpiresAt); left <= 29*time.Second || left > 30*time.Second {
		t.Fatalf("failure is remembered for %v, want just under 30s", left)
	}
}
