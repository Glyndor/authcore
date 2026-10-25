package expiry

import (
	"testing"
	"time"
)

func TestExpired_windowBoundaries(t *testing.T) {
	const ttl = time.Hour
	cases := []struct {
		name    string
		elapsed time.Duration
		want    bool
	}{
		{"just issued", 0, false},
		{"inside the window", 30 * time.Minute, false},
		{"exactly the ttl", ttl, false},
		{"one nanosecond past the ttl", ttl + time.Nanosecond, true},
		{"far past the ttl", 48 * time.Hour, true},
		{"slightly in the future", -30 * time.Second, false},
		{"exactly the future skew", -FutureSkew, false},
		{"one nanosecond past the future skew", -FutureSkew - time.Nanosecond, true},
		{"far in the future", -24 * time.Hour, true},
	}
	for _, c := range cases {
		if got := Expired(c.elapsed, ttl); got != c.want {
			t.Errorf("%s: Expired(%v, %v) = %v, want %v", c.name, c.elapsed, ttl, got, c.want)
		}
	}
}
