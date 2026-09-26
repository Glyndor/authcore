package totp

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

// hotpOracle is RFC 4226 written apart from the package: HMAC-SHA1 over the
// big-endian step, dynamic truncation, six digits. The fuzz oracle below
// compares Verify against it rather than against the package's own
// generator, so a shared mistake cannot pass.
func hotpOracle(key []byte, step uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// FuzzVerify drives VerifyStep and Verify with arbitrary secret/code pairs.
// Both inputs come from the network (the secret from the user's stored row,
// the code from the form), so neither must panic. With a fixed clock, a
// code is accepted exactly when the secret decodes to 20 bytes and the code
// is the RFC 4226 value for one of the steps in the window, computed here
// by hotpOracle. Until 2026-09-25 the target discarded both results, so a
// stepMatches that accepted every code passed 3.3 million executions.
func FuzzVerify(f *testing.F) {
	mod, err := New(newFakeProvider(f))
	if err != nil {
		f.Fatalf("totp.New: %v", err)
	}
	fixed := time.Unix(1234567890, 0).UTC()
	mod.clock = clock.Fixed(fixed)
	now := uint64(fixed.Unix()) / timeStep
	skew := uint64(*mod.cfg.SkewSteps)

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
	// The codes that must be accepted: each step of the window, and one
	// just outside it that must not.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret)
	if err != nil {
		f.Fatal(err)
	}
	for step := now - skew; step <= now+skew; step++ {
		f.Add(enr.Secret, hotpOracle(key, step))
	}
	f.Add(enr.Secret, hotpOracle(key, now-skew-1))
	f.Add(enr.Secret, hotpOracle(key, now+skew+1))

	f.Fuzz(func(t *testing.T, secret, code string) {
		// The oracle's verdict: the secret must be exactly 32 base32
		// characters of 20 bytes, and the code must be one of the window's.
		want := false
		if key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err == nil && len(key) == secretLen && len(secret) == 32 {
			for step := now - skew; step <= now+skew; step++ {
				if code == hotpOracle(key, step) {
					want = true
				}
			}
		}

		_, err := mod.VerifyStep(secret, code, 0)
		if (err == nil) != want {
			t.Fatalf("VerifyStep(%q, %q) = %v, oracle says accept=%v", secret, code, err, want)
		}
		// A step already used refuses everything the oracle accepts.
		if _, err := mod.VerifyStep(secret, code, 1<<63); err == nil {
			t.Fatalf("VerifyStep(%q, %q) accepted a code at a step below the recorded one", secret, code)
		}
		// Verify, the recording entry point, agrees with a fresh recorder.
		if err := mod.Verify(context.Background(), secret, code, &memoryRecorder{}); (err == nil) != want {
			t.Fatalf("Verify(%q, %q) = %v, oracle says accept=%v", secret, code, err, want)
		}
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
		h, err := mod.HashRecoveryCode(code)
		if err != nil {
			t.Fatalf("HashRecoveryCode(%q): %v", code, err)
		}
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
