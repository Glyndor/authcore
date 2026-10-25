package totp_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Recovery codes that share a long prefix, as two hand-typed or imported codes
// might, are still told apart: each code finds its own entry and no other, a
// prefix or an extension of a code finds nothing, and the position of the entry
// in the list does not matter.
func TestHostile_Recovery_codesSharingAPrefixAreTotallyOrdered(t *testing.T) {
	m := newModule(t)
	codes := []string{
		"ABCDEFGH-IJKLMNOP",
		"ABCDEFGH-IJKLMNOQ", // differs in the last character
		"ABCDEFGH-IJKLMNPP", // second to last
		"ABCDEFGH-JJKLMNOP", // first of the second half
		"BBCDEFGH-IJKLMNOP", // first character
		"ABCDEFGI-IJKLMNOP", // last of the first half
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		h, err := m.HashRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		hashes[i] = h
	}
	for want, c := range codes {
		if idx, ok := m.VerifyRecoveryCode(c, hashes); !ok || idx != want {
			t.Errorf("%q = %d, %v; want %d, true", c, idx, ok, want)
		}
	}
	// Reversing the list moves every index and changes no verdict.
	rev := make([]string, len(hashes))
	for i, h := range hashes {
		rev[len(hashes)-1-i] = h
	}
	for want, c := range codes {
		if idx, ok := m.VerifyRecoveryCode(c, rev); !ok || idx != len(codes)-1-want {
			t.Errorf("reversed list, %q = %d, %v; want %d, true", c, idx, ok, len(codes)-1-want)
		}
	}
	base := strings.ReplaceAll(codes[0], "-", "")
	for name, near := range map[string]string{
		"one character short": base[:len(base)-1],
		"first half only":     base[:8],
		"one character long":  base + "A",
		"a code twice":        base + base,
		"first char changed":  "C" + base[1:],
		"last char changed":   base[:len(base)-1] + "Z",
	} {
		if idx, ok := m.VerifyRecoveryCode(near, hashes); ok {
			t.Errorf("%s (%q) matched entry %d", name, near, idx)
		}
	}
}

// Every spelling a person might type of one code finds that code: lower case,
// dash anywhere or nowhere, spaces. Spellings that change a character do not.
func TestHostile_Recovery_spellingsOfOneCode(t *testing.T) {
	m := newModule(t)
	enr, err := m.Enroll("recovery@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code := enr.RecoveryCodes[3]
	plain := strings.ReplaceAll(code, "-", "")
	for name, in := range map[string]string{
		"as issued":       code,
		"lower case":      strings.ToLower(code),
		"no dash":         plain,
		"dash moved":      plain[:4] + "-" + plain[4:],
		"spaces for dash": plain[:8] + " " + plain[8:],
		"spaces all over": strings.Join(strings.Split(plain, ""), " "),
		"dashes all over": strings.Join(strings.Split(plain, ""), "-"),
		"leading space":   " " + code,
		"mixed case":      plain[:5] + strings.ToLower(plain[5:10]) + plain[10:],
		"upper-case dash": strings.ToUpper(code),
	} {
		if idx, ok := m.VerifyRecoveryCode(in, enr.RecoveryHashes); !ok || idx != 3 {
			t.Errorf("%s (%q) = %d, %v; want 3, true", name, in, idx, ok)
		}
	}
	for name, in := range map[string]string{
		"fullwidth letters": strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r - 'A' + 'Ａ'
			}
			return r
		}, code),
		"zero width space inside": plain[:5] + "\u200b" + plain[5:],
		"no-break space inside":   plain[:5] + "\u00a0" + plain[5:],
		"tab inside":              plain[:5] + "\t" + plain[5:],
		"digit for letter":        plain[:1] + "0" + plain[2:],
		"empty":                   "",
		"only separators":         " - - ",
	} {
		if idx, ok := m.VerifyRecoveryCode(in, enr.RecoveryHashes); ok {
			t.Errorf("%s (%q) matched entry %d; only ASCII spacing and case may differ", name, in, idx)
		}
	}
}

// The stored list is the application's data and may be anything: empty, huge,
// holding blanks, truncated or upper-cased digests, duplicates. A code finds its
// entry or nothing, a list of ten thousand entries answers fast, and a
// megabyte "code" neither panics nor matches.
func TestHostile_Recovery_hostileStoredLists(t *testing.T) {
	m := newModule(t)
	code := "ABCDEFGH-IJKLMNOP"
	good, _ := m.HashRecoveryCode(code)

	for name, list := range map[string][]string{
		"nil":                nil,
		"empty strings":      {"", "", ""},
		"truncated digest":   {good[:63]},
		"digest plus suffix": {good + "0"},
		"upper-cased digest": {strings.ToUpper(good)},
		"digest with space":  {" " + good},
		"unrelated digests":  {strings.Repeat("0", 64), strings.Repeat("f", 64)},
	} {
		if idx, ok := m.VerifyRecoveryCode(code, list); ok {
			t.Errorf("%s: matched entry %d", name, idx)
		}
	}

	dup := []string{"x", good, "y", good}
	if idx, ok := m.VerifyRecoveryCode(code, dup); !ok || dup[idx] != good {
		t.Errorf("duplicated entry: = %d, %v; the index must point at a matching entry", idx, ok)
	}

	big := make([]string, 10000)
	for i := range big {
		big[i] = fmt.Sprintf("%064x", i)
	}
	big[7777] = good
	start := time.Now()
	if idx, ok := m.VerifyRecoveryCode(code, big); !ok || idx != 7777 {
		t.Errorf("10000 entries: = %d, %v; want 7777, true", idx, ok)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("a 10000-entry list took %s", d)
	}

	start = time.Now()
	if _, ok := m.VerifyRecoveryCode(strings.Repeat("A", 1<<20), big); ok {
		t.Error("a megabyte code matched")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a megabyte code against 10000 entries took %s", d)
	}
}
