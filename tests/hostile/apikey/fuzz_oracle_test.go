package apikey_test

import (
	"strings"
	"testing"
)

// FuzzHashAgainstOracle compares Hash and Verify with the independent HMAC on
// arbitrary strings (Verify only on those shaped like a key), and requires that a one-byte change to either the key or
// the stored hash is a mismatch.
func FuzzHashAgainstOracle(f *testing.F) {
	pepper := randomPepper(f)
	m := moduleWith(f, pepper)
	f.Add("ak_00112233445566778899aabbccddeeff_" + strings.Repeat("ab", 32))
	f.Add("")
	f.Add("\x00\xff")

	f.Fuzz(func(t *testing.T, key string) {
		stored := oracleHash(pepper, key)
		if got, err := m.Hash(key); err != nil || got != stored {
			t.Fatalf("Hash = %q, %v; oracle %q", got, err, stored)
		}
		if _, err := m.ParseID(key); err != nil {
			if m.Verify(key, stored) {
				t.Fatal("Verify accepted a string that is not shaped like a key")
			}
			return
		}
		if !m.Verify(key, stored) {
			t.Fatal("Verify refused the oracle's hash")
		}
		if m.Verify(key+"\x00", stored) {
			t.Fatal("Verify accepted a key with a byte appended")
		}
		flipped := []byte(stored)
		flipped[0] ^= 1
		if m.Verify(key, string(flipped)) {
			t.Fatal("Verify accepted a hash with a character changed")
		}
		if m.Verify(key, stored+"0") || m.Verify(key, stored[:len(stored)-1]) {
			t.Fatal("Verify accepted a hash of the wrong length")
		}
	})
}

// FuzzParseIDIsExactOrRefuses mutates a real key and asks that ParseID either
// refuses or returns exactly the id field of a key that has the one canonical
// shape: prefix, id of 32 lower-case hex, secret of 64 lower-case hex.
func FuzzParseIDIsExactOrRefuses(f *testing.F) {
	m := newModule(f)
	g, err := m.Generate()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(g.Key, uint16(0), byte(0))
	f.Add(g.Key, uint16(5), byte('A'))
	f.Add(g.Key, uint16(40), byte('_'))

	f.Fuzz(func(t *testing.T, key string, at uint16, with byte) {
		if key != "" {
			b := []byte(key)
			b[int(at)%len(b)] = with
			key = string(b)
		}
		id, err := m.ParseID(key)
		if err != nil {
			if id != "" {
				t.Fatalf("a refusal returned an id: %q", id)
			}
			return
		}
		parts := strings.Split(key, "_")
		if len(parts) != 3 || parts[0] != "ak" || parts[1] != id || len(id) != 32 || len(parts[2]) != 64 {
			t.Fatalf("ParseID accepted %q with id %q", key, id)
		}
		for _, p := range parts[1:] {
			if strings.Trim(p, "0123456789abcdef") != "" {
				t.Fatalf("ParseID accepted non-hex or upper-case characters in %q", key)
			}
		}
	})
}
