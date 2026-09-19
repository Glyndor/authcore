package main

import "testing"

func TestStoreInsertRefusesTakenEmail(t *testing.T) {
	db := newStore()

	if !db.insert(user{id: "first", email: "ana@example.com", passwordHash: "hash-1"}) {
		t.Fatal("insert of a free address reported false")
	}
	if db.insert(user{id: "second", email: "ana@example.com", passwordHash: "hash-2"}) {
		t.Error("insert of a taken address reported true")
	}
	if !db.insert(user{id: "third", email: "luz@example.com", passwordHash: "hash-2"}) {
		t.Error("insert of another free address reported false")
	}

	got, ok := db.findByEmail("ana@example.com")
	if !ok || got.id != "first" || got.passwordHash != "hash-1" {
		t.Errorf("account after the refused insert = %+v, want id first and hash-1", got)
	}
}

func TestStoreSwapRefreshHash(t *testing.T) {
	const email = "ana@example.com"

	tests := []struct {
		name       string
		email      string
		current    string
		wantSwap   bool
		wantStored string
	}{
		{name: "stored hash presented", email: email, current: "stored", wantSwap: true, wantStored: "next"},
		{name: "another hash presented", email: email, current: "other", wantSwap: false, wantStored: "stored"},
		{name: "empty hash presented", email: email, current: "", wantSwap: false, wantStored: "stored"},
		{name: "unknown account", email: "luz@example.com", current: "stored", wantSwap: false, wantStored: "stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newStore()
			db.insert(user{id: "id", email: email})
			db.setRefreshHash(email, "stored")

			if got := db.swapRefreshHash(tt.email, tt.current, "next"); got != tt.wantSwap {
				t.Errorf("swapRefreshHash = %v, want %v", got, tt.wantSwap)
			}
			if got, _ := db.findByEmail(email); got.refreshHash != tt.wantStored {
				t.Errorf("stored hash = %q, want %q", got.refreshHash, tt.wantStored)
			}
		})
	}
}

// A hash can be swapped out once. The second redemption presents a hash that
// is no longer the stored one and must change nothing.
func TestStoreSwapRefreshHashConsumesOnce(t *testing.T) {
	const email = "ana@example.com"
	db := newStore()
	db.insert(user{id: "id", email: email})
	db.setRefreshHash(email, "stored")

	if !db.swapRefreshHash(email, "stored", "first-winner") {
		t.Fatal("first swap of the stored hash reported false")
	}
	if db.swapRefreshHash(email, "stored", "second-winner") {
		t.Error("second swap of the same hash reported true")
	}
	if got, _ := db.findByEmail(email); got.refreshHash != "first-winner" {
		t.Errorf("stored hash = %q, want %q", got.refreshHash, "first-winner")
	}
}

func TestStoreFindByRefreshHash(t *testing.T) {
	db := newStore()
	db.insert(user{id: "never-logged-in", email: "luz@example.com"})
	db.insert(user{id: "logged-in", email: "ana@example.com"})
	db.setRefreshHash("ana@example.com", "stored")

	if got, ok := db.findByRefreshHash("stored"); !ok || got.id != "logged-in" {
		t.Errorf("findByRefreshHash(stored) = %+v, %v, want the logged-in account", got, ok)
	}
	if got, ok := db.findByRefreshHash(""); ok {
		t.Errorf("findByRefreshHash of the empty hash matched %+v, want no account", got)
	}
	if got, ok := db.findByRefreshHash("other"); ok {
		t.Errorf("findByRefreshHash(other) matched %+v, want no account", got)
	}
}

func TestStoreSetRefreshHashUnknownAccount(t *testing.T) {
	db := newStore()
	if db.setRefreshHash("ana@example.com", "hash") {
		t.Error("setRefreshHash for an unknown account reported true")
	}
}
