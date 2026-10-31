package recovery_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// FuzzVerifyRecoveryCode drives VerifyRecoveryCode with arbitrary code
// input against five hash-list shapes:
//   - nil
//   - empty
//   - freshly minted (the hashes from a fresh Enroll)
//   - oversized by count: 4096 deterministic 64-hex-character strings,
//     none of them the hash of any real code, followed by the freshly
//     minted hashes appended at the end
//   - oversized by size: a single 1<<20-character string of "a",
//     followed by the freshly minted hashes appended at the end
//
// The code comes from the user (and so is adversarial); the hashes come
// from the database (and so can be any byte sequence the application
// stored). VerifyRecoveryCode must never panic and must never report a
// match for a code that was not actually minted by this module: for any
// non-empty list, ok must be true exactly when the HMAC-SHA256 of the
// code under the library's pepper appears in the list, and the
// returned index must point at that hash; for nil and empty it must
// always be false.
func FuzzVerifyRecoveryCode(f *testing.F) {
	mod, err := totp.New(fakeProvider{keys: fakeKeys{secret: []byte("0123456789abcdef0123456789abcdef")}})
	if err != nil {
		f.Fatalf("totp.New: %v", err)
	}
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		f.Fatalf("Enroll: %v", err)
	}
	stored := enr.RecoveryHashes

	// Build the oversized shapes once, outside f.Fuzz, so each
	// iteration reuses the same slices rather than rebuilding them.
	oversizedA := make([]string, 4096+len(stored))
	for i := 0; i < 4096; i++ {
		sum := sha256.Sum256([]byte(strconv.Itoa(i)))
		oversizedA[i] = hex.EncodeToString(sum[:])
	}
	copy(oversizedA[4096:], stored)

	oversizedB := make([]string, 1+len(stored))
	oversizedB[0] = strings.Repeat("a", 1<<20)
	copy(oversizedB[1:], stored)

	cases := [][]string{nil, {}, stored, oversizedA, oversizedB, {stored[0], "invalid", stored[0]}}

	// Seeds: real codes from this module, plus adversarial garbage
	// that must not be accepted. The last recovery code hashes to the
	// last element of every list above, so it exercises "matched at the
	// very end of an oversized list" on every ordinary test run. The
	// first code alone did not: a scan that skipped the final element
	// was measured passing with only that seed on 2026-09-19.
	f.Add(enr.RecoveryCodes[0])
	f.Add(enr.RecoveryCodes[len(enr.RecoveryCodes)-1])
	f.Add("")
	f.Add("AAAA1111-BBBB2222")
	f.Add("\x00\x00\x00")
	f.Add(strings.Repeat("A", 1024))

	f.Fuzz(func(t *testing.T, code string) {
		// Each variation is fed as a sub-call rather than as a
		// fuzzer argument because Go fuzzing accepts only a limited
		// set of types in the signature.
		h, valid := referenceRecoveryHash(code)
		gotHash, err := mod.HashRecoveryCode(code)
		if err == nil && gotHash != h {
			t.Fatalf("hash=%q; reference=%q", gotHash, h)
		}
		if err != nil {
			t.Fatalf("HashRecoveryCode(%q): %v", code, err)
		}
		for _, hashes := range cases {
			want := -1
			for i, e := range hashes {
				if valid && e == h {
					want = i
				}
			}

			idx, ok := mod.VerifyRecoveryCode(code, hashes)

			// nil and empty must always reject, regardless of code.
			if len(hashes) == 0 {
				if ok || idx != 0 {
					t.Fatalf("VerifyRecoveryCode(%q, len=%d) returned ok=true; want false",
						code, len(hashes))
				}
				continue
			}

			if want == -1 {
				if ok || idx != 0 {
					t.Fatalf("VerifyRecoveryCode(%q) accepted code whose hash %q is not in list; got idx=%d",
						code, h, idx)
				}
				continue
			}

			if !ok {
				t.Fatalf("VerifyRecoveryCode(%q) rejected code whose hash %q is in list at index %d",
					code, h, want)
			}
			if idx != want {
				t.Fatalf("VerifyRecoveryCode(%q) returned idx=%d pointing at %q, want %q",
					code, idx, hashes[idx], h)
			}
		}
	})
}

func referenceRecoveryHash(code string) (string, bool) {
	// Preserve arbitrary bytes; normalization only folds ASCII.
	normalized := []byte(strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", ""))
	for i, c := range normalized {
		if c >= 'a' && c <= 'z' {
			normalized[i] = c - 32
		}
	}
	mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	mac.Write(normalized)
	return hex.EncodeToString(mac.Sum(nil)), len(normalized) > 0 && len(normalized) <= 16
}
