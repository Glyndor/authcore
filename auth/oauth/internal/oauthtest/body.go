package oauthtest

import (
	"fmt"
	"strings"
)

// ResponseCap is the 1 MiB size guard every response reader in auth/oauth
// applies.
const ResponseCap = 1 << 20

// PaddedBodyAt builds a JSON object of EXACTLY limit bytes, ending in `"}`,
// so the whole object is read by the limit reader: the closing quote and
// brace fit inside the cap.
func PaddedBodyAt(limit int, prefix, suffix string) []byte {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("PaddedBodyAt: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	inner := strings.Repeat("a", limit-len(prefix)-len(suffix))
	return []byte(prefix + inner + suffix)
}

// PaddedBodyOver builds a JSON object of EXACTLY limit+1 bytes. The first
// limit bytes are identical to PaddedBodyAt followed by one extra "a", so
// the cap cut at the limit reader stops one byte before the suffix, inside
// the "pad" string: the closing quote and brace are never read.
func PaddedBodyOver(limit int, prefix, suffix string) []byte {
	if got := len(prefix) + len(suffix); got > limit {
		panic(fmt.Sprintf("PaddedBodyOver: prefix+suffix is %d bytes, larger than limit %d", got, limit))
	}
	inner := strings.Repeat("a", limit-len(prefix)-len(suffix)+1)
	return []byte(prefix + inner + suffix)
}
