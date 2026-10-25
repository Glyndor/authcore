package strictjson_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/strictjson"
)

// FuzzCheckAgreesWithDecoders compares the two readings encoding/json offers
// of an object: a map keyed by exact name, and a struct matched without regard
// to case. An object Check accepts must read the same through both, and must
// survive being written out again.
func FuzzCheckAgreesWithDecoders(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"exp":1,"type":"a","sub":"s"}`, `{"exp":1,"exp":2}`, `{"EXP":1}`,
		`{"sub":"a","Sub":"b"}`, `{"type":"a","type":"b"}`, `{"x":{"x":1,"x":2}}`,
		`[1]`, `{"a":`, `{"Kid":1}`,
	} {
		f.Add([]byte(s))
	}
	known := []string{"exp", "type", "sub"}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if strictjson.Check(raw, known...) != nil {
			return
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return // not an object, or not JSON: Check leaves that to the caller
		}
		var s struct {
			Exp  json.RawMessage `json:"exp"`
			Type json.RawMessage `json:"type"`
			Sub  json.RawMessage `json:"sub"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return
		}
		for name, got := range map[string]json.RawMessage{"exp": s.Exp, "type": s.Type, "sub": s.Sub} {
			if !bytes.Equal(m[name], got) {
				t.Fatalf("accepted %q but %q reads %s by name and %s by struct", raw, name, m[name], got)
			}
		}
		again, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("re-encode %q: %v", raw, err)
		}
		var m2 map[string]json.RawMessage
		if err := json.Unmarshal(again, &m2); err != nil || len(m2) != len(m) || !reflect.DeepEqual(keys(m), keys(m2)) {
			t.Fatalf("accepted %q but its re-encoding %q reads differently (%v)", raw, again, err)
		}
		if strictjson.Check(again, known...) != nil {
			t.Fatalf("accepted %q but refuses its re-encoding %q", raw, again)
		}
	})
}

func keys(m map[string]json.RawMessage) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}
