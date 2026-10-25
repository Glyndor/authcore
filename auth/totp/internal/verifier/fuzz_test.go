package verifier_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/totp/internal/secret"
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
	mod := newTOTP(f)
	fixed := time.Unix(1234567890, 0).UTC()
	mod.clock = clock.Fixed(fixed)
	now := uint64(fixed.Unix()) / timeStep
	skew := uint64(mod.skew)

	// Seed with realistic and adversarial inputs.
	sec, err := secret.New()
	if err != nil {
		f.Fatalf("secret.New: %v", err)
	}
	f.Add(sec, "000000")
	f.Add(sec, "999999")
	f.Add(sec, "")
	f.Add(sec, "123456")
	f.Add("not-base32!@#", "123456")
	f.Add("", "123456")
	f.Add(sec, "abcdef")
	f.Add(sec, "12345")
	f.Add(sec, "1234567")
	f.Add(sec, "０１２３４５") // fullwidth digits
	// The codes that must be accepted: each step of the window, and one
	// just outside it that must not.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sec)
	if err != nil {
		f.Fatal(err)
	}
	for step := now - skew; step <= now+skew; step++ {
		f.Add(sec, hotpOracle(key, step))
	}
	f.Add(sec, hotpOracle(key, now-skew-1))
	f.Add(sec, hotpOracle(key, now+skew+1))

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
