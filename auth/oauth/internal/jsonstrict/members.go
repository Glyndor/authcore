package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
)

// ErrMembers reports member names with more than one reading in one object.
var ErrMembers = errors.New("JSON object carries ambiguous member names")

// UniqueMembers refuses repeated member names, including escaped equivalents
// and case aliases, in every object. Names in separate objects are independent.
// When canonical names are supplied, case aliases of those top-level members
// are refused even when written once. Other extension names remain allowed.
// Syntax errors are left to the operation's decoder.
//
// The scan walks the bytes once and allocates only for member names: a string
// value is skipped, never copied, so a response at its size cap costs no more
// than it did before the check.
func UniqueMembers(raw []byte, canonical ...string) error {
	// A nil map marks an array frame; an object frame holds the names seen.
	var stack []map[string]struct{}
	// wantName is true while the next string in an object frame is a member name.
	wantName := false
	for i := 0; i < len(raw); {
		switch c := raw[i]; c {
		case ' ', '\t', '\r', '\n', ',':
			i++
			if c == ',' {
				wantName = len(stack) > 0 && stack[len(stack)-1] != nil
			}
		case '{':
			stack = append(stack, make(map[string]struct{}))
			wantName = true
			i++
		case '[':
			stack = append(stack, nil)
			wantName = false
			i++
		case '}', ']':
			if len(stack) == 0 {
				return nil
			}
			stack = stack[:len(stack)-1]
			wantName = false
			i++
		case ':':
			wantName = false
			i++
		case '"':
			end := stringEnd(raw, i)
			if end < 0 {
				return nil
			}
			if wantName {
				if err, ok := recordName(stack, raw[i:end], canonical); !ok {
					return nil
				} else if err != nil {
					return err
				}
				wantName = false
			}
			i = end
		default:
			// A number, true, false or null: skip to the next structural byte.
			i = scalarEnd(raw, i)
		}
	}
	return nil
}

// recordName registers the member name quoted in text on the innermost object.
// ok is false when the name cannot be decoded, which is left to the caller's
// decoder; err is ErrMembers when the name repeats or aliases another.
func recordName(stack []map[string]struct{}, text []byte, canonical []string) (err error, ok bool) {
	var name string
	if json.Unmarshal(text, &name) != nil {
		return nil, false
	}
	if len(stack) == 1 {
		for _, exact := range canonical {
			if name != exact && strings.EqualFold(name, exact) {
				return ErrMembers, true
			}
		}
	}
	name = foldName(name)
	names := stack[len(stack)-1]
	if _, exists := names[name]; exists {
		return ErrMembers, true
	}
	names[name] = struct{}{}
	return nil, true
}

// scalarEnd returns the index of the structural byte that ends the number,
// true, false or null starting at raw[start].
func scalarEnd(raw []byte, start int) int {
	i := start
	for i < len(raw) && !strings.ContainsRune(" \t\r\n,:{}[]\"", rune(raw[i])) {
		i++
	}
	return i
}

// stringEnd returns the index just past the string that opens at raw[start],
// or -1 when it never closes.
func stringEnd(raw []byte, start int) int {
	for i := start + 1; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

// foldName gives every rune in a Unicode simple-fold cycle the same spelling,
// matching encoding/json's case-insensitive field matching.
func foldName(name string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, name)
}
