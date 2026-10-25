package idtoken

import (
	"encoding/json"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// StringClaim returns the string value at key, or "" when absent or not a string.
func StringClaim(m gjwt.MapClaims, key string) string {
	s, _ := m[key].(string)
	return s
}

// NumericClaim returns the value at key and reports whether it is a JSON number
// (float64 or json.Number). gjwt.MapClaims holds NumericDate claims as
// float64, but a token decoded via UseNumber arrives as json.Number; both count
// as numeric per RFC 7519.
func NumericClaim(m gjwt.MapClaims, key string) (any, bool) {
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

// BoolClaim reads a boolean claim, tolerating the string forms ("true"/"false")
// some providers emit for email_verified.
func BoolClaim(m gjwt.MapClaims, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// AudienceClaim returns the "aud" claim as a list, accepting the string and
// array spellings; non-string members are dropped.
func AudienceClaim(m gjwt.MapClaims) []string {
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
