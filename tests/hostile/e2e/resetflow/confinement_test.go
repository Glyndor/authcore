// Package resetflow attacks password reset and account activation built on
// auth/credential the way docs/modules/credential.md tells an application to
// build them: one table of pending hashes per purpose, a Verify that binds the
// purpose and the subject of the endpoint being called, and a single-statement
// consume. The adversary reads every token it was ever sent, chooses which
// endpoint to present it at, and races itself.
package resetflow

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

const ttl = 10 * time.Minute

// world is one deployment with the two tables a typical application keeps.
type world struct {
	cred       *credential.Credential
	resets     *hostiletest.TokenTable
	activation *hostiletest.TokenTable
}

func newWorld(t *testing.T) *world {
	t.Helper()
	e := hostiletest.NewEnv(t)
	return &world{
		cred:       e.Credential(t, credential.Config{TTL: ttl}),
		resets:     hostiletest.NewTokenTable(),
		activation: hostiletest.NewTokenTable(),
	}
}

// issue mints a token for purpose and subject and stores its hash in table.
func (w *world) issue(t *testing.T, table *hostiletest.TokenTable, purpose, subject string, at time.Time) string {
	t.Helper()
	issued, err := w.cred.Issue(purpose, subject)
	if err != nil {
		t.Fatal(err)
	}
	table.Put(subject, hostiletest.TokenRow{Hash: issued.Hash, IssuedAt: at})
	return issued.Token
}

// A token mailed for one purpose is useless at the endpoint of another, whether
// the application keeps one table per purpose or, carelessly, one for both: the
// purpose the endpoint passes to Verify is what binds it.
func TestE2E_Reset_aTokenOfOnePurposeFailsAtAnother(t *testing.T) {
	w := newWorld(t)
	resetToken := w.issue(t, w.resets, "reset", "alice", time.Now())
	activateToken := w.issue(t, w.activation, "activate", "alice", time.Now())

	if err := w.activation.Redeem(w.cred, "activate", "alice", resetToken); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("reset token at the activation endpoint = %v, want ErrInvalidCredential", err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", activateToken); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("activation token at the reset endpoint = %v, want ErrInvalidCredential", err)
	}
	// One shared table: the row holds the reset hash, the activation endpoint
	// still passes its own purpose.
	if err := w.resets.Redeem(w.cred, "activate", "alice", resetToken); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("reset token with the activation purpose over the reset row = %v, want ErrInvalidCredential", err)
	}
	if w.resets.Len() != 1 || w.activation.Len() != 1 {
		t.Error("a refused redemption consumed a row")
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", resetToken); err != nil {
		t.Errorf("the genuine reset token after the failed attempts = %v, want accepted", err)
	}
}

// Purposes that differ by a character, a case, a space or by where a boundary
// sits between purpose and subject never stand in for each other.
func TestE2E_Reset_neighbouringPurposesAndSubjectsDoNotCollide(t *testing.T) {
	w := newWorld(t)
	type pair struct{ purpose, subject string }
	base := pair{"reset", "alice"}
	token := w.issue(t, w.resets, base.purpose, base.subject, time.Now())
	row, _ := w.resets.Get(base.subject)

	neighbours := []pair{
		{"Reset", "alice"}, {"reset ", "alice"}, {" reset", "alice"}, {"rese", "alice"}, {"resett", "alice"},
		{"reset", "Alice"}, {"reset", "alice "}, {"reset", "alic"}, {"reset", "alice2"},
		{"resetalice", ""}, {"res", "etalice"}, {"resetx", "alice"[1:]}, {"reseta", "lice"}, {"rese", "talice"},
		{"reset\x00", "alice"}, {"reset", "\x00alice"}, {"reset\x00alice", "x"}, {"", "x"},
	}
	for _, n := range neighbours {
		err := w.cred.Verify(n.purpose, n.subject, token, row.Hash, time.Now())
		if err == nil {
			t.Errorf("(%q, %q) verified the token of (%q, %q)", n.purpose, n.subject, base.purpose, base.subject)
		}
	}
	if err := w.cred.Verify(base.purpose, base.subject, token, row.Hash, time.Now()); err != nil {
		t.Fatalf("the genuine pair = %v", err)
	}
}

// A token of one subject presented for another: against the other's own row,
// against its own, and with the subject swapped in the request.
func TestE2E_Reset_aTokenOfOneSubjectFailsForAnother(t *testing.T) {
	w := newWorld(t)
	aliceToken := w.issue(t, w.resets, "reset", "alice", time.Now())
	bobToken := w.issue(t, w.resets, "reset", "bob", time.Now())

	if err := w.resets.Redeem(w.cred, "reset", "bob", aliceToken); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("alice's token on bob's row = %v, want ErrInvalidCredential", err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", bobToken); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("bob's token on alice's row = %v, want ErrInvalidCredential", err)
	}
	// Alice's request names alice but carries bob's row hash, as an
	// application with a broken lookup would: the subject binds anyway.
	bobRow, _ := w.resets.Get("bob")
	if err := w.cred.Verify("reset", "alice", aliceToken, bobRow.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("alice's token over bob's hash = %v, want ErrInvalidCredential", err)
	}
	if w.resets.Len() != 2 {
		t.Error("a refused redemption consumed a row")
	}
}

// Another deployment's token (another managed secret) never verifies here, even
// for the same purpose and subject.
func TestE2E_Reset_aTokenFromAnotherDeploymentFails(t *testing.T) {
	w := newWorld(t)
	w.issue(t, w.resets, "reset", "alice", time.Now())
	foreign := hostiletest.NewEnv(t).Credential(t, credential.Config{TTL: ttl})
	issued, err := foreign.Issue("reset", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", issued.Token); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("foreign token = %v, want ErrInvalidCredential", err)
	}
	row, _ := w.resets.Get("alice")
	if err := foreign.Verify("reset", "alice", issued.Token, row.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("foreign module over the local hash = %v, want ErrInvalidCredential", err)
	}
}

// Wrong guesses cannot burn a victim's pending token, and a wrong token never
// reports expiry (which would say the row exists and is old).
func TestE2E_Reset_guessingDoesNotConsumeOrLeak(t *testing.T) {
	w := newWorld(t)
	token := w.issue(t, w.resets, "reset", "alice", time.Now().Add(-time.Hour))
	for i := 0; i < 200; i++ {
		guess := fmt.Sprintf("guess-%d", i)
		if err := w.resets.Redeem(w.cred, "reset", "alice", guess); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Fatalf("guess %d on an expired row = %v, want ErrInvalidCredential (never ErrExpired)", i, err)
		}
	}
	if w.resets.Len() != 1 {
		t.Fatal("guesses consumed the row")
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", token); !errors.Is(err, credential.ErrExpired) {
		t.Errorf("the right token on the old row = %v, want ErrExpired", err)
	}
	if w.resets.Len() != 1 {
		t.Error("an expired redemption consumed the row")
	}
}
