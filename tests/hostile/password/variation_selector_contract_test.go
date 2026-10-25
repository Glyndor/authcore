package password_test

import "testing"

// CONTRACT, not a defect: variation selectors are accepted in a password and
// are not folded. A password is secret input, not an identifier, so
// "Correct-Horse-9" and "Correct-Horse-9" followed by U+FE0F (an emoji
// presentation selector, which a keyboard may add on its own) are different
// passwords: both are accepted by the policy, and a hash of one does not verify
// the other. Refusing the selector would reject passwords typed with an emoji
// keyboard; folding it would make two byte-different secrets equivalent. If
// this test fails because the module changed either way, update
// docs/modules/password.md in the same change.
func TestContract_Password_variationSelectorsAreAcceptedAndNotFolded(t *testing.T) {
	m := newModule(t, lowCost())
	for name, sel := range map[string]string{
		"VS16 emoji presentation": "️",
		"VS1 text presentation":   "︀",
		"supplementary VS17":      "\U000e0100",
		"Mongolian FVS1":          "᠋",
	} {
		withSel := strong + sel
		if err := m.ValidatePolicy(withSel); err != nil {
			t.Errorf("%s: refused (%v); the contract is that it is accepted", name, err)
			continue
		}
		hash, err := m.Hash(withSel)
		if err != nil {
			t.Fatalf("%s: Hash: %v", name, err)
		}
		if ok, err := m.Verify(withSel, hash); err != nil || !ok {
			t.Errorf("%s: own password does not verify: %v, %v", name, ok, err)
		}
		if ok, _ := m.Verify(strong, hash); ok {
			t.Errorf("%s: the password without the selector verified; the contract is that it does not fold", name)
		}
	}
}
