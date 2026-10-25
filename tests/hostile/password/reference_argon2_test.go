package password_test

// The reference here is golang.org/x/crypto/argon2 called directly, with the
// PHC string written and read by hand. A hash the module makes must be the
// hash the reference computes, and a hash the reference makes must verify in
// the module, so neither side can drift into a private dialect.

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/password"
)

// refHash writes the PHC string for plaintext under the given cost and salt,
// the way every Argon2 implementation does.
func refHash(plaintext string, m, t uint32, p uint8, salt []byte) string {
	key := argon2.IDKey([]byte(norm.NFC.String(plaintext)), salt, t, m, p, 32)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// refParse reads the cost, salt and key back out of a PHC string.
func refParse(t testing.TB, hash string) (m, it uint32, p uint8, salt, key []byte) {
	t.Helper()
	f := strings.Split(hash, "$")
	if len(f) != 6 || f[1] != "argon2id" || f[2] != "v=19" {
		t.Fatalf("not an argon2id v19 PHC string: %q", hash)
	}
	var pp uint32
	if _, err := fmt.Sscanf(f[3], "m=%d,t=%d,p=%d", &m, &it, &pp); err != nil {
		t.Fatalf("parameters of %q: %v", hash, err)
	}
	var err error
	if salt, err = base64.RawStdEncoding.DecodeString(f[4]); err != nil {
		t.Fatal(err)
	}
	if key, err = base64.RawStdEncoding.DecodeString(f[5]); err != nil {
		t.Fatal(err)
	}
	return m, it, uint8(pp), salt, key
}

// Every hash the module writes is the reference's hash of the NFC form of the
// password, under the salt and cost it recorded.
func TestHostile_Reference_moduleHashesAreTheReferenceHashes(t *testing.T) {
	for _, cfg := range []password.Config{
		lowCost(),
		{Memory: 8 * 1024, Iterations: 3, Parallelism: 4},
		{Memory: 9 * 1024, Iterations: 2, Parallelism: 255},
		{Memory: 16 * 1024, Iterations: 1, Parallelism: 2},
	} {
		m := newModule(t, cfg)
		for _, pw := range []string{strong, "Café-Muñoz-9", "Decomposed-e\u0301-9!", "日本語-Passw0rd-A!"} {
			hash, err := m.Hash(pw)
			if err != nil {
				t.Fatalf("Hash(%q): %v", pw, err)
			}
			mem, it, par, salt, key := refParse(t, hash)
			if mem != cfg.Memory || it != cfg.Iterations || par != cfg.Parallelism {
				t.Errorf("hash records m=%d,t=%d,p=%d, want %+v", mem, it, par, cfg)
			}
			want := argon2.IDKey([]byte(norm.NFC.String(pw)), salt, it, mem, par, 32)
			if string(want) != string(key) {
				t.Errorf("Hash(%q) under %+v differs from the reference key", pw, cfg)
			}
		}
	}
}

// Hashes written by the reference verify in the module across the cost table,
// including the corners of the parallelism range, and a different password
// does not.
func TestHostile_Reference_referenceHashesVerifyInTheModule(t *testing.T) {
	m := newModule(t, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	salt := []byte("0123456789abcdef")
	for _, mem := range []uint32{8192, 9000} {
		for _, it := range []uint32{1, 2, 8} {
			for _, par := range []uint8{1, 8} {
				hash := refHash(strong, mem, it, par, salt)
				if ok, err := m.Verify(strong, hash); err != nil || !ok {
					t.Errorf("m=%d t=%d p=%d: Verify = %v, %v", mem, it, par, ok, err)
				}
				if ok, err := m.Verify(strong+"x", hash); err != nil || ok {
					t.Errorf("m=%d t=%d p=%d: a different password verified or errored: %v, %v", mem, it, par, ok, err)
				}
			}
		}
	}
}

// Two accounts that share a salt (an import that reused one, say) still verify
// each under its own password and never under the other's: the salt is part of
// the input but not a substitute for the password.
func TestHostile_Reference_aSharedSaltDoesNotMixAccounts(t *testing.T) {
	m := newModule(t, lowCost())
	salt := []byte("shared-salt-0000")
	alice, bob := "Alice-Passw0rd-1!", "Bobby-Passw0rd-2!"
	hashA := refHash(alice, 8192, 1, 1, salt)
	hashB := refHash(bob, 8192, 1, 1, salt)
	if hashA == hashB {
		t.Fatal("test bug: two passwords gave one hash")
	}
	for _, tc := range []struct {
		pw, hash string
		want     bool
	}{{alice, hashA, true}, {bob, hashB, true}, {alice, hashB, false}, {bob, hashA, false}} {
		if ok, err := m.Verify(tc.pw, tc.hash); err != nil || ok != tc.want {
			t.Errorf("Verify(%q) = %v, %v; want %v", tc.pw, ok, err, tc.want)
		}
	}
	// The module itself never reuses a salt: fresh hashes of one password differ.
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		h, err := m.Hash(alice)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, s, _ := refParse(t, h)
		if seen[string(s)] {
			t.Fatal("the module reused a salt")
		}
		seen[string(s)] = true
	}
}
