package verifier_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestCollidingCodeCannotReopen(t *testing.T) {
	const secret = "AAAAAAAAAABZ6AAAAAAAAAAAAAAAAAAA"
	const code = "604344"
	const first, last, current = 31556151, 31556158, 31556160
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []uint64{first, last} {
		if got := collisionHOTP(key, step); got != code {
			t.Fatalf("independent HOTP at %d = %s, want %s", step, got, code)
		}
	}
	m := newTOTP(t, Config{SkewSteps: Int(10)})
	atUnix(m, current*30, 0)
	if got, err := m.VerifyStep(secret, code, 0); err != nil || got != last {
		t.Errorf("VerifyStep = %d, %v; want latest matching step %d", got, err, last)
	}
	rec := &memoryRecorder{}
	if err := m.Verify(context.Background(), secret, code, rec); err != nil {
		t.Fatalf("first Verify = %v, want nil", err)
	}
	if rec.step != last {
		t.Errorf("recorded step = %d, want %d", rec.step, last)
	}

	// Move the older match outside the window while the newer one remains valid.
	atUnix(m, current*30+60, 0)
	if got, err := m.VerifyStep(secret, code, 0); err != nil || got != last {
		t.Fatalf("unused code after clock advance = %d, %v; want %d", got, err, last)
	}
	if got, err := m.VerifyStep(secret, code, last); got != 0 || !errors.Is(err, ErrCodeReused) {
		t.Errorf("used step after clock advance = %d, %v; want 0 and ErrCodeReused", got, err)
	}
	if err := m.Verify(context.Background(), secret, code, rec); !errors.Is(err, ErrCodeReused) {
		t.Errorf("replay after clock advance = %v, want ErrCodeReused", err)
	}
	if rec.step != last || rec.callCount() != 2 {
		t.Errorf("recorder = step %d, calls %d; want step %d, calls 2", rec.step, rec.callCount(), last)
	}
}

// Derive the fixed collision independently of the production HOTP helper.
func collisionHOTP(key []byte, step uint64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
