package apikey_test

import "testing"

// The module keeps its own copy of the secret it was given. Whoever supplied
// the buffer may reuse or clear it afterwards without changing a single hash.
func TestHostile_PepperIsCopiedAtConstruction(t *testing.T) {
	pepper := randomPepper(t)
	m := moduleWith(t, pepper)
	before, err := m.Generate()
	if err != nil {
		t.Fatal(err)
	}

	for i := range pepper {
		pepper[i] = 0
	}

	if !m.Verify(before.Key, before.Hash) {
		t.Error("a key generated before the source buffer was cleared no longer verifies")
	}
	after, err := m.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !m.Verify(after.Key, after.Hash) {
		t.Error("a key generated after the source buffer was cleared does not verify")
	}
	if h, err := m.Hash(before.Key); err != nil || h != before.Hash {
		t.Error("Hash of an earlier key changed after the source buffer was cleared")
	}
}
