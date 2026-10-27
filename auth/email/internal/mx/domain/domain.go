// Package domain extracts the domain of a normalized email address and checks
// that it fits DNS's size limits.
package domain

import "strings"

// Of extracts the domain part of a normalized email address.
// Returns "" if address contains no '@'.
func Of(address string) string {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return ""
	}
	return address[i+1:]
}

// Plausible reports whether domain fits DNS's size limits: at most 253
// bytes and labels of 1 to 63. Verify checks it before the cache or the
// resolver, so a caller passing an unvalidated value cannot pin a megabyte
// "domain" in the cache for the cache's lifetime.
func Plausible(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}
