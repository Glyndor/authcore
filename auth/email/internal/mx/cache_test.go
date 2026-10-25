package mx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// ---- VerifyDomain() tests ---------------------------------------------------

// primeCache directly writes a cache entry, bypassing DNS, so we can test
// cache hit behaviour without network access.
func primeCache(m *Verifier, domain string, hasMX bool, ttl time.Duration) {
	m.cache.mu.Lock()
	m.cache.entries[domain] = cacheEntry{hasMX: hasMX, expiresAt: time.Now().Add(ttl)}
	m.cache.mu.Unlock()
}

func TestVerifyDomain_cacheDropsEntryWhenFull(t *testing.T) {
	m := newVerifier()

	// Fill the cache to maxCacheSize with live entries.
	m.cache.mu.Lock()
	for i := range maxCacheSize {
		m.cache.entries[fmt.Sprintf("live%d.example", i)] = cacheEntry{
			hasMX:     true,
			expiresAt: time.Now().Add(time.Hour),
		}
	}
	m.cache.mu.Unlock()

	// Storing a new entry must be silently dropped when cache is full.
	m.cache.store("new.example", cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)})

	m.cache.mu.RLock()
	_, ok := m.cache.entries["new.example"]
	m.cache.mu.RUnlock()

	if ok {
		t.Error("store must drop new entries silently when cache is at maxCacheSize")
	}
}

// store is the only eviction there is since #135 removed the background
// goroutine: when the cache is full it drops the expired entries and then
// admits the new one. Until 2026-09-25 the test for eviction called a helper
// nothing in production called, so this path could be deleted with the suite
// green, and a full cache would then never admit another domain.
func TestStore_evictsExpiredEntriesWhenFull(t *testing.T) {
	m := newVerifier()
	m.cache.mu.Lock()
	for i := 0; i < maxCacheSize-1; i++ {
		m.cache.entries[fmt.Sprintf("stale%d.example", i)] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(-time.Second)}
	}
	m.cache.entries["live.example"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)}
	m.cache.mu.Unlock()

	m.cache.store("new.example", cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)})

	m.cache.mu.RLock()
	_, newOk := m.cache.entries["new.example"]
	_, liveOk := m.cache.entries["live.example"]
	_, staleOk := m.cache.entries["stale0.example"]
	size := len(m.cache.entries)
	m.cache.mu.RUnlock()

	if !newOk {
		t.Error("a full cache of expired entries must admit the new domain")
	}
	if !liveOk {
		t.Error("eviction must keep live entries")
	}
	if staleOk {
		t.Error("eviction must remove expired entries")
	}
	if size != 2 {
		t.Errorf("cache holds %d entries after eviction, want 2", size)
	}
}

func TestVerifyDomain_dnsFailureCachesNegativeBriefly(t *testing.T) {
	m := newVerifier()
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	_ = m.Verify(context.Background(), "user@unreachable.example")

	// Second call must hit the cache (no second DNS attempt).
	// We verify by reading the cache directly.
	m.cache.mu.RLock()
	entry, ok := m.cache.entries["unreachable.example"]
	m.cache.mu.RUnlock()
	if !ok {
		t.Fatal("expected a cache entry after DNS failure")
	}
	if entry.hasMX {
		t.Error("failed DNS lookup must cache hasMX=false")
	}
	if time.Until(entry.expiresAt) > 31*time.Second {
		t.Errorf("negative DNS failure TTL should be ≤30 s, got %v", time.Until(entry.expiresAt))
	}
}
