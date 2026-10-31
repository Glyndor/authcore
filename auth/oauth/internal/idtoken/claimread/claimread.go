// Package claimread reads typed values out of an ID token's decoded claims,
// tolerating the spellings providers emit.
package claimread

import (
	"encoding/json"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// String returns the string value at key, or "" when absent or not a string.
func String(m gjwt.MapClaims, key string) string {
	s, _ := m[key].(string)
	return s
}

// Numeric returns the value at key and reports whether it is a JSON number
// (float64 or json.Number). gjwt.MapClaims holds NumericDate claims as
// float64, but a token decoded via UseNumber arrives as json.Number; both count
// as numeric per RFC 7519.
func Numeric(m gjwt.MapClaims, key string) (any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	switch v.(type) {
	case float64, json.Number:
		return v, true
	}
	return nil, false
}

// The range of seconds a time claim may hold: 1970-01-01T00:00:00Z up to
// 9999-12-31T23:59:59Z, the same range auth/jwt enforces. A NumericDate outside
// it cannot have been written by a sane issuer, and a number too large for
// time.Time wraps to a date in the distant past that a time check reads as
// already elapsed.
const (
	minNumericDate = 0
	maxNumericDate = 253402300799
)

// DateInRange reports whether the claim at key is absent or a NumericDate
// inside the supported range. A value that is present but not a number, or not
// finite, is out of range; the presence and type checks live with the caller.
func DateInRange(m gjwt.MapClaims, key string) bool {
	v, ok := m[key]
	if !ok {
		return true
	}
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case json.Number:
		var err error
		if f, err = n.Float64(); err != nil {
			return false
		}
	default:
		return false
	}
	// The whole seconds must lie in range, as auth/jwt reads them with Unix():
	// a fraction below the epoch truncates to zero. False for NaN and infinities.
	return f > minNumericDate-1 && f < maxNumericDate+1
}

// Bool reads a boolean claim, tolerating the string forms ("true"/"false")
// some providers emit for email_verified.
func Bool(m gjwt.MapClaims, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// Audience returns the "aud" claim as a list, accepting the string and
// array spellings; non-string members are dropped.
func Audience(m gjwt.MapClaims) []string {
	switch v := m["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
