package apikey_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
)

// The stored hash is documented as hex(HMAC-SHA256(pepper, key)) over the
// whole key string. oracleHash is that, from the standard library alone.
func oracleHash(pepper []byte, key string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

func moduleWith(t testing.TB, pepper []byte, cfg ...apikey.Config) *apikey.APIKey {
	t.Helper()
	m, err := apikey.New(newProviderWithPepper(t, pepper), cfg...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHostile_Oracle_generatedAndHashedKeysMatchTheIndependentHMAC(t *testing.T) {
	pepper := randomPepper(t)
	for _, prefix := range []string{"ak", "a", "0", "sk9", strings.Repeat("z", 16)} {
		m := moduleWith(t, pepper, apikey.Config{Prefix: prefix})
		for range 50 {
			g, err := m.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if want := oracleHash(pepper, g.Key); g.Hash != want {
				t.Fatalf("prefix %q: Generate().Hash = %s, oracle %s", prefix, g.Hash, want)
			}
			if h, err := m.Hash(g.Key); err != nil || h != g.Hash {
				t.Fatalf("Hash disagrees with Generate: %v", err)
			}
			if !m.Verify(g.Key, oracleHash(pepper, g.Key)) {
				t.Fatal("Verify refused the oracle's hash of a generated key")
			}
		}
	}
}

// Hash takes any string, because a caller hashes whatever a client presented
// before parsing it. Awkward and huge strings give the oracle's answer in
// bounded time, and Verify refuses every one of them because none has the shape
// of a generated key.
func TestHostile_Oracle_arbitraryAndHugeStringsHashLikeTheOracle(t *testing.T) {
	pepper := randomPepper(t)
	m := moduleWith(t, pepper)
	for name, key := range map[string]string{
		"empty":          "",
		"one byte":       "k",
		"NUL":            "\x00",
		"invalid UTF-8":  "ak_\xff\xfe_\xc3\x28",
		"newline":        "ak_00\n",
		"a megabyte":     strings.Repeat("a", 1<<20),
		"thirty-two MiB": strings.Repeat("\x00", 32<<20),
	} {
		start := time.Now()
		got, err := m.Hash(key)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		stored := oracleHash(pepper, key)
		if got != stored {
			t.Errorf("%s: Hash = %s, oracle %s", name, got, stored)
		}
		if m.Verify(key, stored) {
			t.Errorf("%s: Verify accepted a string that is not shaped like a key", name)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

// Another pepper is another namespace: the same key hashes differently, and a
// stored hash from one deployment verifies nothing in another.
func TestHostile_Oracle_aHashFromAnotherPepperVerifiesNothing(t *testing.T) {
	a, b := moduleWith(t, randomPepper(t)), moduleWith(t, randomPepper(t))
	g, _ := a.Generate()
	if b.Verify(g.Key, g.Hash) {
		t.Error("a hash from another pepper verified")
	}
	if h, _ := b.Hash(g.Key); h == g.Hash {
		t.Error("two peppers produced the same hash")
	}
}
