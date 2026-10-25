package urlcheck

import "testing"

// TestLoopbackExceptionCoversTheWholeRange covers the plaintext exception.
// Only loopback may be http; everything else must still be refused.
func TestLoopbackExceptionCoversTheWholeRange(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":          true,
		"127.0.0.1":          true,
		"127.0.0.2":          true,
		"127.1.2.3":          true,
		"::1":                true,
		"10.0.0.1":           false,
		"192.168.1.1":        false,
		"example.com":        false,
		"localhost.evil.com": false,
		"":                   false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
