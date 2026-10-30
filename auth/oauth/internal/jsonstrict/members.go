package jsonstrict

import (
	"encoding/json"
	"errors"
	"strings"
)

// ErrMembers reports member names with more than one reading in one object.
var ErrMembers = errors.New("JSON object carries ambiguous member names")

// maxDepth is how many open objects the scan keeps a name table for. Deeper
// levels are only counted: no member the client reads sits that deep, and a
// document that nests further is accepted as before, with the names below the
// limit left unchecked.
const maxDepth = 64

// UniqueMembers refuses a repeated member name in an object, down to maxDepth
// levels. Names are compared as the decoder reads them, so `"id"` and
// `"id"` are one name; names that differ only in case are different names,
// as they are for a map. The exception is the top-level object when canonical
// names are supplied: those members are read into struct fields, which
// encoding/json matches without regard to case, so a spelling that matches a
// canonical name only by case is refused even when it is written once. Every
// other member keeps its own spelling. Syntax errors are left to the
// operation's decoder.
//
// The scan walks the bytes once. A string value is skipped, never copied, and
// the name tables are reused by depth, so a body at its size cap costs a
// constant multiple of its size however many objects it holds.
func UniqueMembers(raw []byte, canonical ...string) error {
	var sc scan
	for i := 0; i < len(raw); {
		switch c := raw[i]; c {
		case ' ', '\t', '\r', '\n':
			i++
		case ',':
			sc.comma()
			i++
		case ':':
			sc.wantName = false
			i++
		case '{', '[':
			sc.open(c)
			i++
		case '}', ']':
			if !sc.close() {
				return nil
			}
			i++
		case '"':
			end := stringEnd(raw, i)
			if end < 0 {
				return nil
			}
			if sc.wantName && sc.beyond == 0 {
				ok, err := recordName(sc.frames[sc.depth-1], raw[i:end], sc.depth == 1, canonical)
				if !ok {
					return nil
				}
				if err != nil {
					return err
				}
				sc.wantName = false
			}
			i = end
		default:
			// A number, true, false or null: skip to the next structural byte.
			i = scalarEnd(raw, i)
		}
	}
	return nil
}

// scan is the state of one UniqueMembers pass.
type scan struct {
	// frames[d] is the name table of the open object at depth d, reused by
	// every object that opens at that depth; isObject tells an object from an
	// array there.
	frames   []map[string]struct{}
	isObject []bool
	depth    int
	// wantName is true while the next string in an object is a member name.
	wantName bool
	// beyond counts the levels open below maxDepth, which have no name table.
	beyond int
}

func (s *scan) comma() {
	s.wantName = s.beyond == 0 && s.depth > 0 && s.isObject[s.depth-1]
}

func (s *scan) open(c byte) {
	if s.depth >= maxDepth {
		s.beyond++
		s.wantName = false
		return
	}
	if s.depth == len(s.frames) {
		s.frames = append(s.frames, make(map[string]struct{}))
		s.isObject = append(s.isObject, false)
	}
	s.isObject[s.depth] = c == '{'
	if c == '{' {
		clear(s.frames[s.depth])
	}
	s.depth++
	s.wantName = c == '{'
}

// close ends the innermost level. It reports false on a closer with nothing
// open, which is a syntax error left to the operation's decoder.
func (s *scan) close() bool {
	s.wantName = false
	if s.beyond > 0 {
		s.beyond--
		return true
	}
	if s.depth == 0 {
		return false
	}
	s.depth--
	return true
}

// recordName registers the member name quoted in text in names. ok is false
// when the name cannot be decoded, which is left to the operation's decoder;
// err is ErrMembers when the name repeats or, at the top level, spells a
// canonical name with other capitalisation.
func recordName(names map[string]struct{}, text []byte, top bool, canonical []string) (ok bool, err error) {
	name, plain := plainName(text)
	if !plain {
		if json.Unmarshal(text, &name) != nil {
			return false, nil
		}
	}
	if top {
		for _, exact := range canonical {
			if name != exact && strings.EqualFold(name, exact) {
				return true, ErrMembers
			}
		}
	}
	if _, exists := names[name]; exists {
		return true, ErrMembers
	}
	names[name] = struct{}{}
	return true, nil
}

// plainName returns the name inside text when it holds printable ASCII and no
// escape, so it needs no JSON decoding.
func plainName(text []byte) (string, bool) {
	inner := text[1 : len(text)-1]
	for _, b := range inner {
		if b == '\\' || b < 0x20 || b >= 0x7f {
			return "", false
		}
	}
	return string(inner), true
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
