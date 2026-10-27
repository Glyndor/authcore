package jwks

import "time"

// SetClockForTest installs the clock before concurrent lookups start.
func SetClockForTest(c *Cache, now func() time.Time) { c.now = now }
