package credential_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// An independent implementation of the documented binding: hex(HMAC-SHA256(
// pepper, len(purpose)||purpose || len(subject)||subject || len(token)||token))
// with each length a big-endian uint32. The module's stored hash is compared
// with it on inputs the table tests do not reach.

func oracleHash(pepper []byte, purpose, subject, token string) string {
	mac := hmac.New(sha256.New, pepper)
	for _, f := range []string{purpose, subject, token} {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f))))
		mac.Write([]byte(f))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func TestHostile_Framing_issuedHashMatchesTheOracleOnAwkwardInputs(t *testing.T) {
	pepper := randomPepper(t)
	m := newModuleWith(t, pepper)
	for name, in := range map[string][2]string{
		"ascii":                 {"reset", "alice"},
		"NUL bytes":             {"re\x00set", "\x00alice\x00"},
		"invalid UTF-8":         {"\xff\xfe", "\xc3\x28"},
		"length-looking prefix": {"\x00\x00\x00\x05reset", "alice"},
		"one byte each":         {"p", "s"},
		"unicode":               {"réinitialisation", "аlice"},
		"a megabyte purpose":    {strings.Repeat("p", 1<<20), "s"},
		"a megabyte subject":    {"p", strings.Repeat("s", 1<<20)},
		"eight megabytes":       {"p", strings.Repeat("\x01", 8<<20)},
	} {
		start := time.Now()
		issued, err := m.Issue(in[0], in[1])
		if err != nil {
			t.Errorf("%s: Issue: %v", name, err)
			continue
		}
		if want := oracleHash(pepper, in[0], in[1], issued.Token); issued.Hash != want {
			t.Errorf("%s: hash %s, oracle %s", name, issued.Hash, want)
		}
		if err := m.Verify(in[0], in[1], issued.Token, oracleHash(pepper, in[0], in[1], issued.Token), time.Now()); err != nil {
			t.Errorf("%s: Verify of the oracle's hash: %v", name, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

// With a shared boundary: every way of cutting one string into purpose,
// subject and token yields a different hash, so shifting a byte between fields
// never reproduces a stored value. The token is fixed to the same string in all
// cuts by passing it through Verify with a stored hash from the oracle.
func TestHostile_Framing_everyCutOfOneStringIsADifferentBinding(t *testing.T) {
	pepper := randomPepper(t)
	m := newModuleWith(t, pepper)
	const joined = "reset-alice-token-material"
	seen := map[string][3]string{}
	for i := 1; i < len(joined); i++ {
		for j := i + 1; j < len(joined); j++ {
			p, s, tok := joined[:i], joined[i:j], joined[j:]
			h := oracleHash(pepper, p, s, tok)
			if prev, dup := seen[h]; dup {
				t.Fatalf("cuts %q and %q share a hash", prev, [3]string{p, s, tok})
			}
			seen[h] = [3]string{p, s, tok}
			// The module accepts exactly its own cut.
			if err := m.Verify(p, s, tok, h, time.Now()); err != nil {
				t.Fatalf("cut %d/%d: %v", i, j, err)
			}
			// A neighbouring cut presented against this hash is refused.
			if j+1 < len(joined) {
				if err := m.Verify(p, joined[i:j+1], joined[j+1:], h, time.Now()); err == nil {
					t.Fatalf("cut %d/%d verified as its neighbour", i, j)
				}
			}
		}
	}
}
