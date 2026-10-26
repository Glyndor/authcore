package field

import (
	"errors"
	"testing"
)

func TestField_nilReceiverRefusesEveryCall(t *testing.T) {
	var m *Field
	if _, err := m.Encrypt("a"); !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Encrypt: %v", err)
	}
	if _, err := m.Decrypt("a"); !errors.Is(err, ErrNotInitialised) {
		t.Errorf("Decrypt: %v", err)
	}
	if _, err := m.BlindIndex("a"); !errors.Is(err, ErrNotInitialised) {
		t.Errorf("BlindIndex: %v", err)
	}
}
