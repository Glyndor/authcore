package plaintext

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// bcrypt reads at most 72 bytes of its input, so two passwords that agree on
// the first 72 bytes are one password there. Argon2id hashes everything, and
// the module must not truncate on the way in: a long passphrase that differs
// only at the end is a different password at every length that matters.
func TestHostile_Sizes_noPrefixTruncationAtAnyBoundary(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.Relaxed(1024))
	for _, n := range []int{71, 72, 73, 127, 128, 129, 255, 256, 257, 1023, 1024} {
		pw := strings.Repeat("p", n-1) + "a"
		hash, err := m.Hash(pw)
		if err != nil {
			t.Fatalf("length %d: Hash: %v", n, err)
		}
		if ok, err := m.Verify(pw, hash); err != nil || !ok {
			t.Errorf("length %d: own password: %v, %v", n, ok, err)
		}
		for name, other := range map[string]string{
			"last byte changed":  strings.Repeat("p", n-1) + "b",
			"one byte appended":  pw + "x",
			"one byte removed":   pw[:n-1],
			"first byte changed": "q" + pw[1:],
		} {
			if ok, _ := m.Verify(other, hash); ok {
				t.Errorf("length %d: %s verified against the original", n, name)
			}
		}
	}
}

// Bounds are in runes, not bytes: 1024 four-byte characters (4 KiB) fit, 1025
// do not, and an ASCII password at 1024 fits at a quarter of the bytes.
func TestHostile_Sizes_policyCountsRunesAtTheMaximum(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.Relaxed(1024))
	for name, tc := range map[string]struct {
		pw string
		ok bool
	}{
		"1024 ASCII":     {strings.Repeat("a", 1024), true},
		"1025 ASCII":     {strings.Repeat("a", 1025), false},
		"1024 emoji":     {strings.Repeat("\U0001f600", 1024), true},
		"1025 emoji":     {strings.Repeat("\U0001f600", 1025), false},
		"1024 CJK":       {strings.Repeat("日", 1024), true},
		"1 MiB of ASCII": {strings.Repeat("a", 1<<20), false},
		"4 MiB of emoji": {strings.Repeat("\U0001f600", 1<<20), false},
	} {
		start := time.Now()
		_, err := m.Hash(tc.pw)
		if tc.ok && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if !tc.ok && !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%s: %v, want ErrWeakPassword", name, err)
		}
		if !tc.ok {
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("%s: refusing took %s; it must not hash first", name, d)
			}
		}
	}
}

// Verify applies no policy, so it must still cope with a plaintext of any
// size: a megabyte of input is hashed in full, matches the reference's hash of
// it, and costs the same order of time as a short password.
// The fixed resource ceiling supersedes the unbounded-size expectation above:
// oversized credentials are refused independently of the password policy.
func TestHostile_Sizes_verifyRejectsOversizedPlaintext(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	big := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	hash := hostiletest.RefHash(big, 8192, 1, 1, []byte("0123456789abcdef"))

	start := time.Now()
	ok, err := m.Verify(big, hash)
	elapsed := time.Since(start)
	if err != nil || ok {
		t.Fatalf("1 MiB plaintext against its own hash: %v, %v; want false, nil", ok, err)
	}
	if ok, _ := m.Verify(big+"x", hash); ok {
		t.Error("1 MiB plus one byte verified")
	}
	if ok, _ := m.Verify(big[:len(big)-1], hash); ok {
		t.Error("1 MiB minus one byte verified")
	}
	if elapsed > 5*time.Second {
		t.Errorf("verifying a megabyte took %s", elapsed)
	}
}
