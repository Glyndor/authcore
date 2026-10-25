package credential_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
)

// FuzzFramingAgainstOracle checks the module's Verify against the independent
// binding in framing_oracle_test.go on arbitrary purpose, subject and token, and
// asks that moving the boundary between any two fields by one byte is refused.
func FuzzFramingAgainstOracle(f *testing.F) {
	pepper := randomPepper(f)
	m := newModuleWith(f, pepper)
	f.Add("reset", "alice", "tok")
	f.Add("", "", "")
	f.Add("\x00\x00\x00\x05reset", "a", "\xff")
	f.Add("a", "bc", "d")

	f.Fuzz(func(t *testing.T, purpose, subject, token string) {
		stored := oracleHash(pepper, purpose, subject, token)
		if err := m.Verify(purpose, subject, token, stored, time.Now()); err != nil {
			t.Fatalf("the oracle's hash was refused: %v", err)
		}
		if len(subject) > 0 {
			err := m.Verify(purpose+subject[:1], subject[1:], token, stored, time.Now())
			if !errors.Is(err, credential.ErrInvalidCredential) {
				t.Fatalf("a boundary moved by one byte verified: %v", err)
			}
		}
		if len(token) > 0 {
			err := m.Verify(purpose, subject+token[:1], token[1:], stored, time.Now())
			if !errors.Is(err, credential.ErrInvalidCredential) {
				t.Fatalf("a boundary moved by one byte verified: %v", err)
			}
		}
		if purpose != "" && subject != "" {
			if issued, err := m.Issue(purpose, subject); err != nil || issued.Hash != oracleHash(pepper, purpose, subject, issued.Token) {
				t.Fatalf("Issue disagrees with the oracle: %v", err)
			}
		}
	})
}
