package model

import (
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

const credTTL = 10 * time.Minute

var (
	purposes = []string{"reset", "activate", "email-change"}
	subjects = []string{"alice", "bob", "carol"}
)

type slot struct{ purpose, subject string }

// issuedToken is a token handed out for a slot, kept after the row is gone so
// the adversary can replay it later.
type issuedToken struct {
	slot  slot
	token string
}

// pending is the oracle's view of one table row.
type pending struct {
	token string
	at    time.Duration
}

// credModel runs the credential module and the one-time-token tables beside a
// model of them: a redemption is accepted exactly when the presented slot has a
// pending row, the token is the one issued for that very slot, and the row is
// younger than the TTL. A row is consumed by an accepted redemption and
// replaced by the next issue.
type credModel struct {
	t      *testing.T
	tr     *trace
	r      *rng
	mod    *credential.Credential
	tables map[string]*hostiletest.TokenTable // one table per purpose
	rows   map[slot]pending
	issued []issuedToken
	now    time.Duration
	seen   map[bool]int // redemptions by the verdict the model expected
}

func newCredModel(t *testing.T, seed uint64) *credModel {
	t.Helper()
	m := &credModel{
		t: t, tr: &trace{seed: seed}, r: &rng{state: seed},
		mod:    hostiletest.NewEnv(t).Credential(t, credential.Config{TTL: credTTL}),
		tables: map[string]*hostiletest.TokenTable{},
		rows:   map[slot]pending{},
		seen:   map[bool]int{},
	}
	for _, p := range purposes {
		m.tables[p] = hostiletest.NewTokenTable()
	}
	return m
}

func (m *credModel) issue() {
	s := slot{pick(m.r, purposes), pick(m.r, subjects)}
	issued, err := m.mod.Issue(s.purpose, s.subject)
	if err != nil {
		m.tr.fail(m.t, "issue: %v", err)
	}
	// The stored timestamp is the real instant minus how far the virtual clock
	// has run past the row's own start, fixed at redemption time below.
	m.tables[s.purpose].Put(s.subject, hostiletest.TokenRow{Hash: issued.Hash})
	m.rows[s] = pending{token: issued.Token, at: m.now}
	m.issued = append(m.issued, issuedToken{slot: s, token: issued.Token})
	m.tr.add("issue %v at=%s", s, m.now)
}

// redeem presents a token at the endpoint of a slot: the document flow, with
// the clock the adversary controls expressed through the row's timestamp.
func (m *credModel) redeem(at slot, token string) {
	table := m.tables[at.purpose]
	row, ok := table.Get(at.subject)
	want := false
	if p, has := m.rows[at]; has {
		want = ok && p.token == token && m.now-p.at < credTTL
	}
	var err error
	switch {
	case !ok:
		err = hostiletest.ErrNoRow
	default:
		issuedAt := time.Now().Add(-(m.now - m.rows[at].at))
		if err = m.mod.Verify(at.purpose, at.subject, token, row.Hash, issuedAt); err == nil && !table.Consume(at.subject, row.Hash) {
			err = hostiletest.ErrConsumed
		}
	}
	m.tr.add("redeem %v age=%s fresh=%v -> %v", at, m.now-m.rows[at].at, m.rows[at].token == token, err == nil)
	m.seen[want]++
	switch got := err == nil; {
	case got && !want:
		m.tr.fail(m.t, "redeem %v: accepted what the model rejects (more permissive)", at)
	case !got && want:
		m.tr.fail(m.t, "redeem %v: rejected what the model accepts (%v)", at, err)
	}
	if err == nil {
		delete(m.rows, at)
	}
}

// crossed is a broken lookup: the hash of one slot's row is checked for a token
// at the endpoint of another slot, with that endpoint's own purpose and subject.
// Only the pair that made the hash may pass.
func (m *credModel) crossed(x, y slot) {
	px, ok := m.rows[x]
	if !ok {
		return
	}
	row, _ := m.tables[x.purpose].Get(x.subject)
	issuedAt := time.Now().Add(-(m.now - px.at))
	err := m.mod.Verify(y.purpose, y.subject, px.token, row.Hash, issuedAt)
	want := x == y && m.now-px.at < credTTL
	m.tr.add("crossed row %v at endpoint %v -> %v", x, y, err == nil)
	m.seen[want]++
	switch got := err == nil; {
	case got && !want:
		m.tr.fail(m.t, "crossed %v at %v: accepted what the model rejects (more permissive)", x, y)
	case !got && want:
		m.tr.fail(m.t, "crossed %v at %v: rejected what the model accepts (%v)", x, y, err)
	}
}

func (m *credModel) step() {
	if len(m.issued) == 0 {
		m.issue()
		return
	}
	prev := pick(m.r, m.issued)
	switch n := m.r.intn(100); {
	case n < 25:
		m.issue()
	case n < 50: // the right token at the right endpoint, maybe spent or replaced since
		m.redeem(prev.slot, prev.token)
	case n < 70: // the token at an endpoint of another purpose or subject
		m.redeem(slot{pick(m.r, purposes), pick(m.r, subjects)}, prev.token)
	case n < 75: // a guess
		m.redeem(prev.slot, prev.token+"x")
	case n < 80:
		m.crossed(prev.slot, slot{pick(m.r, purposes), pick(m.r, subjects)})
	case n < 90:
		d := pick(m.r, []int{1, 1, 5, 9, 10, 11, 60})
		m.now += minutes(d)
		m.tr.add("advance %dm -> %s", d, m.now)
	default: // the application deletes the row, as a password change does
		table := m.tables[prev.slot.purpose]
		if row, ok := table.Get(prev.slot.subject); ok && table.Consume(prev.slot.subject, row.Hash) {
			delete(m.rows, prev.slot)
			m.tr.add("delete row %v", prev.slot)
		}
	}
}

// Whatever the sequence, the library and the tables never accept a redemption
// the model rejects: not a wrong purpose, a wrong subject, a spent token, a
// replaced one, an old one, or a guess.
func TestE2E_Model_credentialNeverAcceptsWhatTheModelRejects(t *testing.T) {
	total := map[bool]int{}
	for _, seed := range seeds(t) {
		m := newCredModel(t, seed)
		for i := 0; i < opsPerSeq; i++ {
			m.step()
		}
		total[true] += m.seen[true]
		total[false] += m.seen[false]
	}
	if total[true] < 100 || total[false] < 100 {
		t.Errorf("redemptions expected accepted=%d rejected=%d, want at least 100 of each", total[true], total[false])
	}
}
