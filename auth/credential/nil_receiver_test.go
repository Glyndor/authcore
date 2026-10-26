package credential

import (
	"errors"
	"testing"
	"time"
)

func TestCredential_nilReceiverRefusesEveryCall(t *testing.T) {
	var m *Credential
	if _, err := m.Issue("p", "s"); !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Issue: %v", err)
	}
	if err := m.Verify("p", "s", "t", "h", time.Now()); !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Verify: %v", err)
	}
}
