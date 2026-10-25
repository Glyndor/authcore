package mx

import (
	"sync"
	"time"
)

// maxCacheSize is the maximum number of domains held in the cache at once.
// When the cache is full and a result arrives, store first drops every
// expired entry; if the cache is still full, the result is not cached and
// the next request for that domain queries DNS again. There is no
// background eviction since #135.
const maxCacheSize = 10_000

// cacheEntry holds the result of a single MX lookup.
type cacheEntry struct {
	hasMX      bool
	dnsFailure bool // true = DNS error, false = confirmed result
	expiresAt  time.Time
}

// cache is the per-domain MX result cache. It owns no goroutine: expired
// entries are ignored on read and dropped lazily when the cache fills.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

func newCache() *cache {
	return &cache{entries: make(map[string]cacheEntry)}
}

// cached returns the cache entry for domain if it exists and has not expired.
func (c *cache) cached(domain string) (cacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[domain]
	c.mu.RUnlock()
	return entry, ok && time.Now().Before(entry.expiresAt)
}

// store writes entry into the cache under write lock. When the cache is full,
// it first drops expired entries to make room (lazy eviction — this is what
// replaces the old background goroutine); if it is still full afterwards the
// entry is dropped and the next lookup retries DNS.
func (c *cache) store(domain string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxCacheSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) < maxCacheSize {
		c.entries[domain] = entry
	}
}
