package claimread

import (
	"encoding/json"
	"strconv"
)

// referenceClaims is the document read as raw member texts, so each reference
// below judges the JSON token a claim was written as, not the Go type the
// decoder happened to pick. It does not call the helpers under test.
type referenceClaims map[string]json.RawMessage

func (r referenceClaims) quoted(key string) (string, bool) {
	raw := r[key]
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// String is the member's text when it is a JSON string, else empty.
func (r referenceClaims) String(key string) string {
	s, _ := r.quoted(key)
	return s
}

// Numeric is the member as the decoder represents a JSON number: a float64, or
// the literal text as a json.Number when the decoder keeps numbers.
func (r referenceClaims) Numeric(key string, useNumber bool) (any, bool) {
	raw := r[key]
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return nil, false
	}
	if useNumber {
		return json.Number(raw), true
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	return f, err == nil
}

// Bool is true for the JSON value true and for the string "true".
func (r referenceClaims) Bool(key string) bool {
	if s, ok := r.quoted(key); ok {
		return s == "true"
	}
	return string(r[key]) == "true"
}

// Audience is the audience as a list: one string, or the string members of an
// array in order. Any other value, or none, gives nil.
func (r referenceClaims) Audience() []string {
	if s, ok := r.quoted("aud"); ok {
		return []string{s}
	}
	raw := r["aud"]
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var members []json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return nil
	}
	out := []string{}
	for _, m := range members {
		if s, ok := (referenceClaims{"m": m}).quoted("m"); ok {
			out = append(out, s)
		}
	}
	return out
}
