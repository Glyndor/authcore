package hostiletest

import (
	"errors"
	"sync"
)

// ErrDuplicate is the UNIQUE violation of the blind index column.
var ErrDuplicate = errors.New("unique constraint violated")

// UserRow is one row of the simulated users table: the email ciphertext and
// its blind index.
type UserRow struct {
	ID       int
	EmailCT  string
	EmailIdx string
}

// Users is a table with `UNIQUE (email_idx)`. Insert is one atomic statement.
type Users struct {
	mu   sync.Mutex
	rows []UserRow
	idx  map[string]int
}

// NewUsers returns an empty table.
func NewUsers() *Users { return &Users{idx: map[string]int{}} }

// Insert adds a row, or fails with ErrDuplicate when the index is taken.
func (u *Users) Insert(ct, idx string) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, taken := u.idx[idx]; taken {
		return 0, ErrDuplicate
	}
	id := len(u.rows) + 1
	u.rows = append(u.rows, UserRow{ID: id, EmailCT: ct, EmailIdx: idx})
	u.idx[idx] = id
	return id, nil
}

// FindByIdx is `SELECT ... WHERE email_idx = ?`.
func (u *Users) FindByIdx(idx string) (UserRow, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	id, ok := u.idx[idx]
	if !ok {
		return UserRow{}, false
	}
	return u.rows[id-1], true
}

// Len is the number of rows.
func (u *Users) Len() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.rows)
}

// Rows returns a copy of every row, what a reader of the database dump sees.
func (u *Users) Rows() []UserRow {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]UserRow(nil), u.rows...)
}
