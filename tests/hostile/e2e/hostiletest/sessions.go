package hostiletest

import (
	"context"
	"errors"
	"sync"
)

// Session is one row of the table the application keeps for logins: the id
// shared by every token of the session and the hash of its current refresh
// token. Only the hash is stored, never the token.
type Session struct {
	ID     string
	UserID string
	Hash   string
}

// Sessions is the sessions table. Every method is one atomic statement.
type Sessions struct {
	mu      sync.Mutex
	rows    map[string]Session // by session id
	retired map[string]string  // refresh hash -> session id that held it
}

// NewSessions returns an empty table.
func NewSessions() *Sessions {
	return &Sessions{rows: map[string]Session{}, retired: map[string]string{}}
}

// Insert stores a new row.
func (s *Sessions) Insert(row Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[row.ID] = row
}

// ByHash is the lookup of step 2 in docs/modules/jwt.md.
func (s *Sessions) ByHash(hash string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.rows {
		if row.Hash == hash {
			return row, true
		}
	}
	return Session{}, false
}

// Swap is `UPDATE sessions SET refresh_hash = next WHERE id = ? AND
// refresh_hash = old`: it reports whether a row changed, and remembers the
// retired hash so a later replay of it can be recognised as reuse.
func (s *Sessions) Swap(id, old, next string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[id]
	if !ok || row.Hash != old {
		return false
	}
	s.retired[old] = id
	row.Hash = next
	s.rows[id] = row
	return true
}

// RetiredOwner reports which session held hash before a rotation replaced it.
func (s *Sessions) RetiredOwner(hash string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.retired[hash]
	return id, ok
}

// Delete removes the row of a session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
}

// Len is the number of live rows.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

// ErrStoreDown is what a Denylist returns while its store is unreachable.
var ErrStoreDown = errors.New("denylist store unreachable")

// Denylist is the revocation store the application hands to the jwt module.
type Denylist struct {
	mu      sync.Mutex
	revoked map[string]bool
	down    bool
	lookups int
}

// NewDenylist returns an empty store.
func NewDenylist() *Denylist { return &Denylist{revoked: map[string]bool{}} }

// Add revokes a session id.
func (d *Denylist) Add(jti string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[jti] = true
}

// SetDown makes every lookup fail, as an unreachable store does.
func (d *Denylist) SetDown(down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.down = down
}

// Lookups is the number of times the store was asked, the traffic a garbage
// token must not cause.
func (d *Denylist) Lookups() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lookups
}

// IsRevoked implements jwt.Denylist.
func (d *Denylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lookups++
	if d.down {
		return false, ErrStoreDown
	}
	return d.revoked[jti], nil
}
