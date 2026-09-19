package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// newUserID returns a UUID v7 (RFC 9562 §5.7) in canonical lower-case form:
// a 48-bit Unix millisecond timestamp followed by 74 random bits.
//
// jwt.CreateTokens rejects any subject that is not a UUID v7, so generate the
// id here and never derive it from the email. The first version of this
// example used the email as the id, and every login returned 500.
//
// It is written against the standard library so the example needs no extra
// dependency. github.com/google/uuid (v1.6 or later, uuid.NewV7) and
// github.com/gofrs/uuid do the same job.
func newUserID() string {
	var b [16]byte

	ms := time.Now().UnixMilli()
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	// crypto/rand.Read never returns an error; it aborts the program if the
	// system source fails.
	_, _ = rand.Read(b[6:])

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
