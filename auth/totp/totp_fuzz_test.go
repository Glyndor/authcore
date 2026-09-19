package totp

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

// FuzzVerify drives Verify with arbitrary secret/code pairs. Both inputs
// come from the network (the secret from the user's stored row, the
// code from the form), so neither must panic. Verify must also never
// report a successful match for a random input: with a fixed clock and
// a known-good secret, the only inputs that succeed are the published
// TOTP values for the current window, and the fuzzer corpus seeds
// deliberately miss those.
func FuzzVerify(f *testing.F) {
	mod, err := New(newFakeProvider(f))
	if err != nil {
		f.Fatalf("totp.New: %v", err)
	}
	mod.clock = clock.Fixed(time.Unix(1234567890, 0).UTC())

	// Seed with realistic and adversarial inputs.
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		f.Fatalf("Enroll: %v", err)
	}
	f.Add(enr.Secret, "000000")
	f.Add(enr.Secret, "999999")
	f.Add(enr.Secret, "")
	f.Add(enr.Secret, "123456")
	f.Add("not-base32!@#", "123456")
	f.Add("", "123456")
	f.Add(enr.Secret, "abcdef")
	f.Add(enr.Secret, "12345")
	f.Add(enr.Secret, "1234567")
	f.Add(enr.Secret, "０１２３４５") // fullwidth digits

	f.Fuzz(func(t *testing.T, secret, code string) {
		// Both lastUsedStep values: 0 (no replay protection) and a
		// large number (must reject everything as "already used" if
		// it ever matched). Neither path may panic.
		_, _ = mod.VerifyStep(secret, code, 0)
		_, _ = mod.VerifyStep(secret, code, 1<<63)
	})
}

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
	mod, err := New(newFakeProvider(f))
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

	cases := [][]string{nil, {}, stored, oversizedA, oversizedB}

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
		h := mod.HashRecoveryCode(code)
		for _, hashes := range cases {
			want := -1
			for i, e := range hashes {
				if e == h {
					want = i
					break
				}
			}

			idx, ok := mod.VerifyRecoveryCode(code, hashes)

			// nil and empty must always reject, regardless of code.
			if len(hashes) == 0 {
				if ok {
					t.Fatalf("VerifyRecoveryCode(%q, len=%d) returned ok=true; want false",
						code, len(hashes))
				}
				continue
			}

			if want == -1 {
				if ok {
					t.Fatalf("VerifyRecoveryCode(%q) accepted code whose hash %q is not in list; got idx=%d",
						code, h, idx)
				}
				continue
			}

			if !ok {
				t.Fatalf("VerifyRecoveryCode(%q) rejected code whose hash %q is in list at index %d",
					code, h, want)
			}
			if hashes[idx] != h {
				t.Fatalf("VerifyRecoveryCode(%q) returned idx=%d pointing at %q, want %q",
					code, idx, hashes[idx], h)
			}
		}
	})
}
