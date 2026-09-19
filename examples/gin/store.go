package main

import (
	"crypto/subtle"
	"sync"
)

// user is one account row. id is the JWT subject and must be a UUID v7;
// email is a login name only and must never stand in for the id.
type user struct {
	id           string
	email        string
	passwordHash string
	refreshHash  string
}

// store is the in-memory stand-in for a database. Each method is one
// statement against that database: keep every check and the write it guards
// inside the same method, under the same lock, exactly as they would share one
// SQL statement or transaction.
type store struct {
	mu    sync.RWMutex
	users map[string]*user // keyed by email
}

func newStore() *store {
	return &store{users: map[string]*user{}}
}

// insert adds u and reports whether it was added. It reports false, and
// changes nothing, when the email is already taken.
//
// Do not split this into "look up, then write": the first version of this
// example wrote unconditionally, and a second registration of an address
// replaced the password hash of the account that owned it. In SQL this is a
// UNIQUE constraint on the email column plus handling the violation, never a
// SELECT followed by an INSERT.
//
// Normalize the address before it becomes a key (auth/email does that);
// without it "Ana@example.com" and "ana@example.com" are two accounts.
func (s *store) insert(u user) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.users[u.email]; taken {
		return false
	}
	s.users[u.email] = &u
	return true
}

// findByEmail returns a copy of the account registered under email.
func (s *store) findByEmail(email string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[email]
	if !ok {
		return user{}, false
	}
	return *u, true
}

// findByRefreshHash returns a copy of the account whose stored refresh hash
// equals hash. An empty hash matches nobody, so an account that never logged
// in cannot be reached through it. In a database this is an indexed lookup on
// the hash column, not a scan.
func (s *store) findByRefreshHash(hash string) (user, bool) {
	if hash == "" {
		return user{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.refreshHash == hash {
			return *u, true
		}
	}
	return user{}, false
}

// setRefreshHash starts a new session for email at login, replacing whatever
// refresh hash was stored. It reports false when the account does not exist.
func (s *store) setRefreshHash(email, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[email]
	if !ok {
		return false
	}
	u.refreshHash = hash
	return true
}

// swapRefreshHash replaces the stored refresh hash with next only while it
// still equals current, and reports whether it did. This is the step that
// consumes a refresh token: of any number of concurrent redemptions of one
// token, exactly one gets true.
//
// Keep the comparison and the write in one critical section. The first version
// of this example matched under a read lock, released it, minted, and then
// wrote unconditionally under the write lock: 32 concurrent redemptions of one
// token returned up to 3 successes. In SQL this is
//
//	UPDATE sessions SET refresh_hash = $next WHERE refresh_hash = $current
//
// and the redemption succeeded only if exactly one row was affected.
func (s *store) swapRefreshHash(email, current, next string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[email]
	if !ok || current == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(u.refreshHash), []byte(current)) != 1 {
		return false
	}
	u.refreshHash = next
	return true
}
