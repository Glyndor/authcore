package main

import "testing"

func TestNewUserIDIsUUIDv7(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newUserID()
		if !uuidV7.MatchString(id) {
			t.Fatalf("newUserID() = %q, not a canonical UUID v7", id)
		}
		if seen[id] {
			t.Fatalf("newUserID() returned %q twice", id)
		}
		seen[id] = true
	}
}
