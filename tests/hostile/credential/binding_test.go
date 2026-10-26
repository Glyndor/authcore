package credential_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/credential"
)

// A token is bound to the purpose and subject it was minted for. Moving it to
// another flow or another user, or reshuffling the boundary between the two,
// is a mismatch and never a success.
func TestHostile_Credential_tokenIsBoundToPurposeAndSubject(t *testing.T) {
	m := newModule(t)
	issued, err := m.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := m.Verify("reset", "alice@example.com", issued.Token, issued.Hash, now); err != nil {
		t.Fatalf("control: %v", err)
	}

	cases := map[string][2]string{
		"other purpose":        {"activate", "alice@example.com"},
		"other subject":        {"reset", "bob@example.com"},
		"both swapped":         {"alice@example.com", "reset"},
		"subject upper case":   {"reset", "Alice@example.com"},
		"subject padded":       {"reset", " alice@example.com"},
		"subject trailing NUL": {"reset", "alice@example.com\x00"},
		"purpose upper case":   {"RESET", "alice@example.com"},
		"purpose prefix":       {"rese", "talice@example.com"},
		"boundary moved":       {"resetalice", "@example.com"},
		"empty purpose":        {"", "alice@example.com"},
		"empty subject":        {"reset", ""},
		"both empty":           {"", ""},
		"purpose joined":       {"reset\x00alice@example.com", ""},
		"decomposed subject":   {"reset", norm.NFD.String("alic\u00e9@example.com")},
	}
	for name, c := range cases {
		err := m.Verify(c[0], c[1], issued.Token, issued.Hash, now)
		if !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("%s: Verify = %v, want ErrInvalidCredential", name, err)
		}
	}

	// The same for a user whose address has non-ASCII characters: composed and
	// decomposed spellings are different subjects until the caller normalises.
	composed := "alic\u00e9@example.com"
	iss2, _ := m.Issue("reset", composed)
	if err := m.Verify("reset", norm.NFD.String(composed), iss2.Token, iss2.Hash, now); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("a decomposed spelling of the subject verified: %v", err)
	}
}

// A token minted for one user cannot be redeemed against another user's row,
// even when the attacker controls which row is looked up.
func TestHostile_Credential_tokenCannotBeMovedToAnotherUsersRow(t *testing.T) {
	m := newModule(t)
	alice, _ := m.Issue("reset", "alice")
	bob, _ := m.Issue("reset", "bob")
	now := time.Now()
	for name, tc := range map[string]struct{ subject, token, hash string }{
		"alice token on bob's row":               {"bob", alice.Token, bob.Hash},
		"alice token as bob":                     {"bob", alice.Token, alice.Hash},
		"alice token, alice subject, bob's hash": {"alice", alice.Token, bob.Hash},
		"bob token on alice's row":               {"alice", bob.Token, alice.Hash},
	} {
		if err := m.Verify("reset", tc.subject, tc.token, tc.hash, now); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("%s: %v, want ErrInvalidCredential", name, err)
		}
	}
}

// Fields are length-prefixed inside the MAC, so no choice of purpose, subject
// and token strings makes two different triples produce the same hash.
func TestHostile_Credential_fieldBoundariesCannotBeShifted(t *testing.T) {
	m := newModule(t)
	now := time.Now()
	issued, _ := m.Issue("ab", "cd")
	for name, tc := range map[string]struct{ purpose, subject, token string }{
		"shift into subject": {"a", "bcd", issued.Token},
		"shift into purpose": {"abc", "d", issued.Token},
		"token prefix moved": {"ab", "cd" + issued.Token[:5], issued.Token[5:]},
		"purpose has token":  {"ab" + "cd", "", issued.Token},
		"NUL separated":      {"ab\x00cd", "", issued.Token},
		"length prefix look": {"\x00\x00\x00\x02ab", "cd", issued.Token},
	} {
		if err := m.Verify(tc.purpose, tc.subject, tc.token, issued.Hash, now); err == nil {
			t.Errorf("%s: a shifted boundary verified", name)
		}
	}
}

// A purpose and subject that carry the very bytes a separator would use cannot
// be re-split into another pair: the lengths, not a delimiter, mark where one
// field ends.
func TestHostile_Credential_embeddedSeparatorBytesCannotReSplitTheFields(t *testing.T) {
	m := newModule(t)
	now := time.Now()
	nul4 := "\x00\x00\x00\x00"
	issued, err := m.Issue("a"+nul4+"b", "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify("a"+nul4+"b", "c", issued.Token, issued.Hash, now); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, pair := range map[string][2]string{
		"split at the first NUL run": {"a", "b" + nul4 + "c"},
		"split at the length prefix": {"a" + nul4, "b\x00c"},
		"everything in the purpose":  {"a" + nul4 + "b" + nul4 + "c", ""},
		"everything in the subject":  {"", "a" + nul4 + "b" + nul4 + "c"},
	} {
		if err := m.Verify(pair[0], pair[1], issued.Token, issued.Hash, now); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("%s: Verify = %v, want ErrInvalidCredential", name, err)
		}
	}
}

// Whatever Verify is handed, a token that is not byte-for-byte the one issued
// fails. Email clients wrap, trim and re-encode links; the module does not
// repair any of it.
func TestHostile_Credential_presentedTokenMustBeExact(t *testing.T) {
	m := newModule(t)
	issued, _ := m.Issue("reset", "alice")
	now := time.Now()
	if len(issued.Token) != 43 {
		t.Fatalf("token is %d characters, want 43 (256 bits)", len(issued.Token))
	}
	for name, token := range map[string]string{
		"empty":            "",
		"truncated":        issued.Token[:len(issued.Token)-1],
		"extended":         issued.Token + "A",
		"trailing newline": issued.Token + "\n",
		"trailing CRLF":    issued.Token + "\r\n",
		"leading space":    " " + issued.Token,
		"trailing space":   issued.Token + " ",
		"trailing NUL":     issued.Token + "\x00",
		"padded":           issued.Token + "=",
		"wrapped line":     issued.Token[:20] + "\n" + issued.Token[20:],
		"url encoded":      strings.ReplaceAll(issued.Token, "-", "%2D"),
		"std alphabet":     strings.NewReplacer("-", "+", "_", "/").Replace(issued.Token),
		"lower cased":      strings.ToLower(issued.Token),
		"upper cased":      strings.ToUpper(issued.Token),
		"doubled":          issued.Token + issued.Token,
		"the hash":         issued.Hash,
		"one MiB":          strings.Repeat("A", 1<<20),
		"quoted":           `"` + issued.Token + `"`,
	} {
		if issued.Token == token {
			continue
		}
		if err := m.Verify("reset", "alice", token, issued.Hash, now); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("%s: Verify = %v, want ErrInvalidCredential", name, err)
		}
	}
	for name, stored := range map[string]string{
		"empty":        "",
		"prefix":       issued.Hash[:len(issued.Hash)-1],
		"extended":     issued.Hash + "0",
		"upper cased":  strings.ToUpper(issued.Hash),
		"trailing NUL": issued.Hash + "\x00",
		"the token":    issued.Token,
	} {
		if err := m.Verify("reset", "alice", issued.Token, stored, now); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("stored hash %s: Verify = %v, want ErrInvalidCredential", name, err)
		}
	}
}
