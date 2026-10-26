package hostiletest

import (
	"errors"
	"sync"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
)

// Outcomes of TokenTable.Redeem that the credential module does not decide.
var (
	// ErrNoRow: the subject has no pending token in this table.
	ErrNoRow = errors.New("no pending token for this subject")
	// ErrConsumed: another request consumed the row between the check and the
	// delete, so this redemption must not be accepted.
	ErrConsumed = errors.New("token consumed by another request")
)

// TokenRow is one pending token: its hash and the instant it was issued.
type TokenRow struct {
	Hash     string
	IssuedAt time.Time
}

// TokenTable is one table of one-time tokens, such as reset_tokens, keyed by
// subject. A deployment keeps one table per purpose.
type TokenTable struct {
	mu   sync.Mutex
	rows map[string]TokenRow
}

// NewTokenTable returns an empty table.
func NewTokenTable() *TokenTable { return &TokenTable{rows: map[string]TokenRow{}} }

// Put stores the pending token of a subject, replacing an earlier one.
func (tt *TokenTable) Put(subject string, row TokenRow) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.rows[subject] = row
}

// Get returns the pending token of a subject.
func (tt *TokenTable) Get(subject string) (TokenRow, bool) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	row, ok := tt.rows[subject]
	return row, ok
}

// Consume is `DELETE ... WHERE subject = ? AND hash = ?`: true only for the
// one caller whose statement removed the row.
func (tt *TokenTable) Consume(subject, hash string) bool {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	row, ok := tt.rows[subject]
	if !ok || row.Hash != hash {
		return false
	}
	delete(tt.rows, subject)
	return true
}

// Len is the number of pending tokens.
func (tt *TokenTable) Len() int {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return len(tt.rows)
}

// Redeem is the documented flow: read the row, let the module verify the token
// against the purpose and subject of THIS endpoint, then consume the row in one
// statement and accept only if that statement consumed it.
func (tt *TokenTable) Redeem(c *credential.Credential, purpose, subject, token string) error {
	row, ok := tt.Get(subject)
	if !ok {
		return ErrNoRow
	}
	if err := c.Verify(purpose, subject, token, row.Hash, row.IssuedAt); err != nil {
		return err
	}
	if !tt.Consume(subject, row.Hash) {
		return ErrConsumed
	}
	return nil
}
