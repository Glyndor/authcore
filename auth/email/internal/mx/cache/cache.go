// Package cache is the per-domain MX result cache behind the mx verifier: it
// keeps confirmed lookups and brief DNS failures, bounded in size, with lazy
// eviction and no goroutine of its own.
package cache

import (
	"sync"
	"time"
)

// MaxSize is the maximum number of domains held in the cache at once.
// When the cache is full and a result arrives, Store first drops every
// expired entry; if the cache is still full, the result is not cached and
// the next request for that domain queries DNS again. There is no
// background eviction since #135.
const MaxSize = 10_000

// Entry holds the result of a single MX lookup.
type Entry struct {
	HasMX      bool
	DNSFailure bool // true = DNS error, false = confirmed result
	ExpiresAt  time.Time
}

// Cache is the per-domain MX result cache. It owns no goroutine: expired
// entries are ignored on read and dropped lazily when the cache fills.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// New returns an empty Cache.
func New() *Cache {
	return &Cache{entries: make(map[string]Entry)}
}

// Cached returns the cache entry for domain if it exists and has not expired.
func (c *Cache) Cached(domain string) (Entry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[domain]
	c.mu.RUnlock()
	return entry, ok && time.Now().Before(entry.ExpiresAt)
}

// Store writes entry into the cache under write lock. When the cache is full,
// it first drops expired entries to make room (lazy eviction — this is what
// replaces the old background goroutine); if it is still full afterwards the
// entry is dropped and the next lookup retries DNS.
func (c *Cache) Store(domain string, entry Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= MaxSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.ExpiresAt) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) < MaxSize {
		c.entries[domain] = entry
	}
}

// Len reports how many entries the cache holds, expired ones included until
// a full cache drops them.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
