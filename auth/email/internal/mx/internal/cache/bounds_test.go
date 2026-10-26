package cache_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/mx/internal/cache"
)

// The cache admits exactly ten thousand live domains.
func TestCacheHoldsExactlyTenThousandLiveDomains(t *testing.T) {
	t.Parallel()
	c := cache.New()
	live := cache.Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Hour)}
	for i := range 10_000 {
		c.Store(fmt.Sprintf("d%d.example", i), live)
	}
	if _, ok := c.Cached("d9999.example"); !ok {
		t.Fatal("the 10000th live domain must be admitted")
	}
	c.Store("one-too-many.example", live)
	if _, ok := c.Cached("one-too-many.example"); ok {
		t.Fatal("the 10001st live domain must be dropped")
	}
}

// A read must not leave the cache locked against the writer that follows.
func TestCachedDoesNotBlockALaterStore(t *testing.T) {
	t.Parallel()
	c := cache.New()
	c.Store("a.example", cache.Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Hour)})
	_, _ = c.Cached("a.example")
	done := make(chan struct{})
	go func() {
		c.Store("b.example", cache.Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Hour)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Store blocked after Cached: the read lock was not released")
	}
}
