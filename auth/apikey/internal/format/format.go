// Package format is the wire shape of an API key, <prefix>_<id>_<secret>:
// how the fields are joined and how a presented key is parsed back into its
// public identifier.
package format

import (
	"encoding/hex"
	"strings"
)

const (
	// IDLen is the size in bytes of the public identifier, hex-encoded to
	// 32 characters (128 bits).
	IDLen = 16
	// SecretLen is the size in bytes of the secret, hex-encoded to 64
	// characters (256 bits).
	SecretLen = 32
)

// Join returns the full key for prefix, id and secret.
func Join(prefix, id, secret string) string {
	return prefix + "_" + id + "_" + secret
}

// ParseID extracts the public identifier from a presented key without
// verifying it.
//
// The full key shape is <prefix>_<id>_<secret>. ParseID accepts exactly that
// three-field shape: an id of 32 lowercase hex characters and a secret of 64
// lowercase hex characters, with nothing before, between or after them except
// the two field separators. It reports false for any other key.
func ParseID(prefix, key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, prefix+"_")
	if !ok {
		return "", false
	}
	id, secretAndTail, ok := strings.Cut(rest, "_")
	if !ok || id == "" {
		return "", false
	}
	// A key from Generate has exactly three fields. Anything after the secret
	// leaves secretAndTail longer than an encoded secret, so the shape check
	// below rejects it; there is no separate extra-field rule to keep in step.
	secret := secretAndTail
	if len(id) != hex.EncodedLen(IDLen) || !isHex(id) {
		return "", false
	}
	if len(secret) != hex.EncodedLen(SecretLen) || !isHex(secret) {
		return "", false
	}
	return id, true
}

// isHex reports whether s is all lowercase hexadecimal digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
