package jsonstrict_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jsonstrict"
)

func TestUniqueMembers(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		ambiguous bool
	}{
		{`{"id":1,"id":2}`, true}, {`{"id":1,"ID":2}`, true}, {`{"id":1,"\u0069d":2}`, true},
		{`{"s":1,"ſ":2}`, true}, {`{"k":1,"K":2}`, true},
		{`{"id":1,"nested":{"id":2,"id":3}}`, true}, {`[{"id":1,"ID":2}]`, true},
		{`{"id":1,"nested":{"id":2},"array":[{"id":3},{"id":4}]}`, false},
		{`{"value":"id","id":"value"}`, false}, {`[]`, false}, {`null`, false},
		{`{`, false}, {`{"id":?}`, false}, {`{"id":1}}`, false}, {`}`, false},
		{`{"id":1} {"id":2}`, false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if err := jsonstrict.UniqueMembers([]byte(tc.raw)); errors.Is(err, jsonstrict.ErrMembers) != tc.ambiguous {
				t.Errorf("ambiguity=%v err=%v", tc.ambiguous, err)
			}
		})
	}
}

func TestCanonicalMembersHaveExactNames(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		ambiguous bool
	}{
		{`{"KID":"key"}`, true}, {`{"kid":"key"}`, false}, {`{"extension":"key"}`, false},
		{`{"nested":{"KID":"key"}}`, false},
	} {
		if err := jsonstrict.UniqueMembers([]byte(tc.raw), "kid"); errors.Is(err, jsonstrict.ErrMembers) != tc.ambiguous {
			t.Errorf("%s: err=%v", tc.raw, err)
		}
	}
}

func FuzzUniqueMembers(f *testing.F) {
	f.Add([]byte(`{"id":1,"id":2}`))
	f.Add([]byte(`{"id":1,"nested":{"id":2}}`))
	f.Add([]byte(`{"k":1,"K":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Repeating a complete member in a valid object must always be refused.
		if len(raw) > 16384 {
			t.Skip()
		}
		_ = jsonstrict.UniqueMembers(raw)
		if json.Valid(raw) {
			duplicate := append([]byte(`{"value":`), raw...)
			duplicate = append(duplicate, []byte(`,"value":`)...)
			duplicate = append(duplicate, raw...)
			duplicate = append(duplicate, '}')
			if !errors.Is(jsonstrict.UniqueMembers(duplicate), jsonstrict.ErrMembers) {
				t.Fatal("repeated member accepted")
			}
		}
	})
}
