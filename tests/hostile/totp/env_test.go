package totp_test

// Fixtures for the hostile TOTP tests. The module reads a real clock, so a
// test that needs a code for a chosen step computes it with an independent
// RFC 4226 implementation and retries when the 30 second step turns over while
// the test is running.

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 4226 test oracle; HMAC-SHA1 is what TOTP specifies.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp"
)

func newProvider(t testing.TB) authcore.Provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	prov, err := authcore.New(authcore.Config{KeyStore: ks})
	if err != nil {
		t.Fatalf("authcore.New: %v", err)
	}
	return prov
}

func newModule(t testing.TB, cfg ...totp.Config) *totp.TOTP {
	t.Helper()
	m, err := totp.New(newProvider(t), cfg...)
	if err != nil {
		t.Fatalf("totp.New: %v", err)
	}
	return m
}

// sharedSecret returns a fresh base32 secret the way Enroll writes it.
func sharedSecret(t testing.TB) string {
	t.Helper()
	enr, err := newModule(t).Enroll("seed@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return enr.Secret
}

// codeAt is an independent RFC 4226 implementation: the six digit code of the
// given 30 second step for a base32 secret.
func codeAt(t testing.TB, secret string, step uint64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	mac := hmac.New(sha1.New, key)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], step)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", n%1_000_000)
}

func stepNow() uint64 { return uint64(time.Now().Unix()) / 30 }

// atStableStep runs fn with the step that is current when it starts. fn
// returns a failure message, or "" when everything held. A run during which
// the 30 second step turned over proves nothing about a code placed "two
// steps ahead", so it is discarded and run again.
func atStableStep(t testing.TB, fn func(step uint64) string) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		before := stepNow()
		msg := fn(before)
		if stepNow() != before {
			continue
		}
		if msg != "" {
			t.Fatal(msg)
		}
		return
	}
	t.Fatal("the 30 second step kept turning over")
}

// memRecorder is the one-row-per-account table the application keeps: the
// highest step already accepted, advanced under a lock.
type memRecorder struct {
	mu   sync.Mutex
	last uint64
	hits int
	fail error
}

func (r *memRecorder) RecordIfNewer(_ context.Context, step uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	if r.fail != nil {
		return r.fail
	}
	if step <= r.last {
		return totp.ErrCodeReused
	}
	r.last = step
	return nil
}
