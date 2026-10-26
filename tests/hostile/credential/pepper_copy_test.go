package credential_test

import (
	"testing"
	"time"
)

// The module keeps its own copy of the secret it was given. Whoever supplied
// the buffer may reuse or clear it afterwards without changing a single hash.
func TestHostile_PepperIsCopiedAtConstruction(t *testing.T) {
	pepper := randomPepper(t)
	m := newModuleWith(t, pepper)
	issued, err := m.Issue("reset", "alice")
	if err != nil {
		t.Fatal(err)
	}

	for i := range pepper {
		pepper[i] = 0
	}

	if err := m.Verify("reset", "alice", issued.Token, issued.Hash, time.Now()); err != nil {
		t.Errorf("a token issued before the source buffer was cleared no longer verifies: %v", err)
	}
	again, err := m.Issue("reset", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify("reset", "alice", again.Token, again.Hash, time.Now()); err != nil {
		t.Errorf("a token issued after the source buffer was cleared does not verify: %v", err)
	}
}
