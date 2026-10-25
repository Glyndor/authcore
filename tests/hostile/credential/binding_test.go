package credential_test

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

// The edges of the validity window, placed a minute or more inside or outside
// so the real clock cannot move the verdict.
func TestHostile_Credential_expiryEdges(t *testing.T) {
	const ttl = 10 * time.Minute
	m := newModule(t, credential.Config{TTL: ttl})
	issued, _ := m.Issue("reset", "alice")
	verify := func(issuedAt time.Time) error {
		return m.Verify("reset", "alice", issued.Token, issued.Hash, issuedAt)
	}
	now := time.Now()

	for name, at := range map[string]time.Time{
		"just issued":        now,
		"inside the window":  now.Add(-ttl + 2*time.Minute),
		"a little in future": now.Add(30 * time.Second),
	} {
		if err := verify(at); err != nil {
			t.Errorf("%s: %v, want nil", name, err)
		}
	}
	for name, at := range map[string]time.Time{
		"just past the ttl":     now.Add(-ttl - 2*time.Minute),
		"a day old":             now.Add(-24 * time.Hour),
		"zero time":             {},
		"unix epoch":            time.Unix(0, 0),
		"two minutes in future": now.Add(2 * time.Minute),
		"an hour in future":     now.Add(time.Hour),
		"year 9999":             time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
		"max time":              time.Unix(1<<62, 0),
		"min time":              time.Unix(-1<<62, 0),
	} {
		if err := verify(at); !errors.Is(err, credential.ErrExpired) {
			t.Errorf("%s: %v, want ErrExpired", name, err)
		}
	}
}

// Whether the token itself was right is not revealed by an expired answer to a
// wrong token: a wrong token always reports a mismatch, however old the row.
func TestHostile_Credential_wrongTokenNeverReportsExpiry(t *testing.T) {
	m := newModule(t)
	issued, _ := m.Issue("reset", "alice")
	wrong, _ := m.Issue("reset", "alice")
	old := time.Now().Add(-48 * time.Hour)
	if err := m.Verify("reset", "alice", wrong.Token, issued.Hash, old); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("wrong token on an old row = %v, want ErrInvalidCredential", err)
	}
	if err := m.Verify("reset", "alice", issued.Token, issued.Hash, old); !errors.Is(err, credential.ErrExpired) {
		t.Fatalf("right token on an old row = %v, want ErrExpired", err)
	}
}

// Single use is the application's half: it deletes the row in the same
// transaction that accepted it. Run through the documented flow, many
// simultaneous redemptions of one token produce exactly one success.
func TestHostile_Credential_concurrentRedemptionYieldsOneWinner(t *testing.T) {
	m := newModule(t)
	issued, _ := m.Issue("reset", "alice")
	issuedAt := time.Now()

	var (
		mu      sync.Mutex
		stored  = map[string]string{"alice": issued.Hash}
		winners atomic.Int64
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)
	// takeRow is the atomic "read and delete" the application's transaction
	// performs: it returns the hash and removes the row, once.
	takeRow := func(user string) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		h, ok := stored[user]
		delete(stored, user)
		return h, ok
	}
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			hash, ok := takeRow("alice")
			if !ok {
				return
			}
			if err := m.Verify("reset", "alice", issued.Token, hash, issuedAt); err == nil {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("%d redemptions succeeded, want 1", got)
	}
	if _, ok := takeRow("alice"); ok {
		t.Fatal("the row survived redemption")
	}
}

// Tokens come from the system's random source: no repeat across a large batch,
// full width, and the hash is not derivable from the token without the pepper.
func TestHostile_Credential_issuedTokensAreFreshAndKeyed(t *testing.T) {
	a, b := newModule(t), newModule(t)
	seen, hashes := map[string]bool{}, map[string]bool{}
	for i := 0; i < 20000; i++ {
		iss, err := a.Issue("reset", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if seen[iss.Token] || hashes[iss.Hash] {
			t.Fatalf("repeat after %d tokens", i)
		}
		seen[iss.Token], hashes[iss.Hash] = true, true
		if len(iss.Token) != 43 || len(iss.Hash) != 64 {
			t.Fatalf("token=%d hash=%d characters", len(iss.Token), len(iss.Hash))
		}
	}
	iss, _ := a.Issue("reset", "alice")
	if err := b.Verify("reset", "alice", iss.Token, iss.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("a token from another deployment verified: %v", err)
	}
}

// Issue refuses the unbound token, and Verify never treats an empty hash or
// token as a match for an empty-input hash.
func TestHostile_Credential_unboundInputsAreRefused(t *testing.T) {
	m := newModule(t)
	if iss, err := m.Issue("", "alice"); iss != nil || !errors.Is(err, credential.ErrEmptyPurpose) {
		t.Errorf("empty purpose: %+v, %v", iss, err)
	}
	if iss, err := m.Issue("reset", ""); iss != nil || !errors.Is(err, credential.ErrEmptySubject) {
		t.Errorf("empty subject: %+v, %v", iss, err)
	}
	if err := m.Verify("", "", "", "", time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("all empty: %v", err)
	}
	big := strings.Repeat("a", 4<<20)
	iss, err := m.Issue("reset", big)
	if err != nil {
		t.Fatalf("a large subject was refused: %v", err)
	}
	if err := m.Verify("reset", big, iss.Token, iss.Hash, time.Now()); err != nil {
		t.Errorf("a large subject does not verify: %v", err)
	}
	if err := m.Verify("reset", big[:len(big)-1], iss.Token, iss.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("a subject one byte shorter verified: %v", err)
	}
}

// Construction and pepper rules.
func TestHostile_Credential_configAndPepperBounds(t *testing.T) {
	for name, cfg := range map[string]credential.Config{
		"zero ttl":     {},
		"negative ttl": {TTL: -time.Second},
		"over a day":   {TTL: 24*time.Hour + time.Nanosecond},
		"max duration": {TTL: time.Duration(1<<63 - 1)},
		"min duration": {TTL: time.Duration(-1 << 63)},
	} {
		if _, err := credential.New(newProviderWithPepper(t, randomPepper(t)), cfg); !errors.Is(err, credential.ErrInvalidConfig) {
			t.Errorf("%s: credential.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	for _, ttl := range []time.Duration{time.Nanosecond, 24 * time.Hour} {
		if _, err := credential.New(newProviderWithPepper(t, randomPepper(t)), credential.Config{TTL: ttl}); err != nil {
			t.Errorf("control: ttl %v refused: %v", ttl, err)
		}
	}
	for name, pepper := range map[string][]byte{"nil": nil, "empty": {}, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33)} {
		if _, err := credential.New(newProviderWithPepper(t, pepper)); !errors.Is(err, credential.ErrInvalidConfig) {
			t.Errorf("pepper %s: credential.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	zero := &credential.Credential{}
	if iss, err := zero.Issue("a", "b"); iss != nil || !errors.Is(err, credential.ErrNotInitialised) {
		t.Errorf("zero value Issue: %+v, %v", iss, err)
	}
	if err := zero.Verify("a", "b", "t", "h", time.Now()); !errors.Is(err, credential.ErrNotInitialised) {
		t.Errorf("zero value Verify: %v", err)
	}
}
