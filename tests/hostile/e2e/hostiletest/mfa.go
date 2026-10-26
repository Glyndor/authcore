package hostiletest

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/totp"
)

// Account is one enrolled second factor as the application stores it: the
// shared secret, the highest accepted step and the unused recovery hashes. It
// is its own totp.StepRecorder, bound to this enrollment.
type Account struct {
	Name   string
	Secret string
	Codes  []string // the printout the user holds; the adversary may copy it

	mu     sync.Mutex
	last   uint64
	hashes []string
}

// Enroll creates an Account through the module.
func Enroll(t testing.TB, m *totp.TOTP, name string) *Account {
	t.Helper()
	enr, err := m.Enroll(name)
	Check(t, err)
	return &Account{Name: name, Secret: enr.Secret, Codes: enr.RecoveryCodes, hashes: slices.Clone(enr.RecoveryHashes)}
}

// RecordIfNewer is the compare-and-advance of the StepRecorder contract.
func (a *Account) RecordIfNewer(_ context.Context, step uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if step <= a.last {
		return totp.ErrCodeReused
	}
	a.last = step
	return nil
}

// LastStep is the highest accepted step.
func (a *Account) LastStep() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
}

// Remaining is the number of unused recovery hashes.
func (a *Account) Remaining() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.hashes)
}

// UseRecovery looks the code up against the stored hashes and then deletes the
// matched hash in a second critical section that re-checks it is still there,
// the "delete where the hash is still unused" statement of the guide. It
// accepts only when it was the one that deleted the hash.
func (a *Account) UseRecovery(m *totp.TOTP, code string) bool {
	a.mu.Lock()
	snapshot := slices.Clone(a.hashes)
	a.mu.Unlock()
	idx, ok := m.VerifyRecoveryCode(code, snapshot)
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	at := slices.Index(a.hashes, snapshot[idx])
	if at < 0 {
		return false
	}
	a.hashes = slices.Delete(a.hashes, at, at+1)
	return true
}

// CodeAt is an independent RFC 4226 implementation, including its own SHA-1 so
// that the repository imports crypto/sha1 only where it is justified: the six
// digit code of a 30 second step for a base32 secret.
func CodeAt(t testing.TB, secret string, step uint64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	Check(t, err)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], step)
	sum := HMACSHA1(key, ctr[:])
	off := sum[len(sum)-1] & 0x0f
	n := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", n%1_000_000)
}

// StepNow is the current 30 second step.
func StepNow() uint64 { return uint64(time.Now().Unix()) / 30 }

// AtStableStep runs fn with the step current when it starts, and runs it again
// when the step turned over meanwhile, because a code placed "two steps ahead"
// proves nothing across a boundary. fn returns "" when everything held.
func AtStableStep(t testing.TB, fn func(step uint64) string) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		before := StepNow()
		msg := fn(before)
		if StepNow() != before {
			continue
		}
		if msg != "" {
			t.Fatal(msg)
		}
		return
	}
	t.Fatal("the 30 second step kept turning over")
}

// sha1Sum is SHA-1 as FIPS 180-4 writes it, kept here so the TOTP oracle shares
// no code, and no import, with the module it checks. It is used only inside an
// HMAC (RFC 2104), where SHA-1's collision weakness does not apply.
func sha1Sum(msg []byte) [20]byte {
	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	padded := append([]byte(nil), msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.BigEndian.AppendUint64(padded, uint64(len(msg))*8)

	for off := 0; off < len(padded); off += 64 {
		var w [80]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(padded[off+4*i:])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5A827999
			case i < 40:
				f, k = b^c^d, 0x6ED9EBA1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8F1BBCDC
			default:
				f, k = b^c^d, 0xCA62C1D6
			}
			a, b, c, d, e = bits.RotateLeft32(a, 5)+f+e+k+w[i], a, bits.RotateLeft32(b, 30), c, d
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	var out [20]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(out[4*i:], v)
	}
	return out
}

// HMACSHA1 is HMAC (RFC 2104) over sha1Sum.
func HMACSHA1(key, msg []byte) []byte {
	if len(key) > 64 {
		sum := sha1Sum(key)
		key = sum[:]
	}
	block := make([]byte, 64)
	copy(block, key)
	inner := make([]byte, 64, 64+len(msg))
	outer := make([]byte, 64, 64+20)
	for i := range block {
		inner[i] = block[i] ^ 0x36
		outer[i] = block[i] ^ 0x5c
	}
	innerSum := sha1Sum(append(inner, msg...))
	outerSum := sha1Sum(append(outer, innerSum[:]...))
	return outerSum[:]
}
