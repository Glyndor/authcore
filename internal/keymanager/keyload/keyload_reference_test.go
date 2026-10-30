package keyload

import (
	"bytes"
	"encoding/hex"
)

// referenceSecret decodes the content of a secret file the way the documented
// contract reads it: whitespace around the hex is ignored, either case is
// accepted, and the value must be 32 bytes that look random. ok is false when
// the file must be refused.
func referenceSecret(data []byte) (secret []byte, ok bool) {
	secret, err := hex.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil || len(secret) != 32 {
		return nil, false
	}
	return secret, !referenceDegenerate(secret)
}

// referenceDegenerate restates the rule for a secret that cannot be
// random-looking: a constant stride, one short block repeated, or fewer than
// twelve different byte values.
func referenceDegenerate(b []byte) bool {
	stride := true
	for i := 2; i < len(b); i++ {
		if b[i]-b[i-1] != b[1]-b[0] {
			stride = false
		}
	}
	if stride {
		return true
	}
	for period := 2; period <= len(b)/2; period++ {
		if bytes.Equal(b[period:], b[:len(b)-period]) {
			return true
		}
	}
	var seen [256]bool
	distinct := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct < 12
}
