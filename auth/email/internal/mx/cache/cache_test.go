package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestVerifyDomain_cacheDropsEntryWhenFull(t *testing.T) {
	c := New()

	// Fill the cache to MaxSize with live entries.
	c.mu.Lock()
	for i := range MaxSize {
		c.entries[fmt.Sprintf("live%d.example", i)] = Entry{
			HasMX:     true,
			ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	c.mu.Unlock()

	// Storing a new entry must be silently dropped when cache is full.
	c.Store("new.example", Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Minute)})

	c.mu.RLock()
	_, ok := c.entries["new.example"]
	c.mu.RUnlock()

	if ok {
		t.Error("store must drop new entries silently when cache is at MaxSize")
	}
}

// store is the only eviction there is since #135 removed the background
// goroutine: when the cache is full it drops the expired entries and then
// admits the new one. Until 2026-09-25 the test for eviction called a helper
// nothing in production called, so this path could be deleted with the suite
// green, and a full cache would then never admit another domain.
func TestStore_evictsExpiredEntriesWhenFull(t *testing.T) {
	c := New()
	c.mu.Lock()
	for i := 0; i < MaxSize-1; i++ {
		c.entries[fmt.Sprintf("stale%d.example", i)] = Entry{HasMX: true, ExpiresAt: time.Now().Add(-time.Second)}
	}
	c.entries["live.example"] = Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.mu.Unlock()

	c.Store("new.example", Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Minute)})

	c.mu.RLock()
	_, newOk := c.entries["new.example"]
	_, liveOk := c.entries["live.example"]
	_, staleOk := c.entries["stale0.example"]
	size := len(c.entries)
	c.mu.RUnlock()

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

func TestCached_returnsALiveEntryAndIgnoresAnExpiredOne(t *testing.T) {
	c := New()
	c.Store("live.example", Entry{HasMX: true, ExpiresAt: time.Now().Add(time.Minute)})
	c.Store("dead.example", Entry{HasMX: true, ExpiresAt: time.Now().Add(-time.Second)})

	if entry, ok := c.Cached("live.example"); !ok || !entry.HasMX {
		t.Errorf("Cached(live) = %+v, %v; want the stored entry", entry, ok)
	}
	if _, ok := c.Cached("dead.example"); ok {
		t.Error("Cached must not return an expired entry")
	}
	if _, ok := c.Cached("absent.example"); ok {
		t.Error("Cached must not invent an entry for an unknown domain")
	}
}

func TestLen_countsEveryStoredEntry(t *testing.T) {
	c := New()
	if got := c.Len(); got != 0 {
		t.Fatalf("a new cache holds %d entries, want 0", got)
	}
	c.Store("a.example", Entry{ExpiresAt: time.Now().Add(time.Minute)})
	c.Store("b.example", Entry{DNSFailure: true, ExpiresAt: time.Now().Add(time.Minute)})
	if got := c.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}
