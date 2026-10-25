package phc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// Verify derives the key with the parameters carried *inside the stored hash*,
// not the module's own config — that is what keeps old hashes valid after the
// work factors are tuned up. It also means a stored string decides how much
// memory and time the verification costs, so the bounds in parsePHC are the
// only thing standing between a hostile or corrupted row and a 16 GiB
// allocation on the next login attempt.
//
// These assert at parsePHC rather than through Verify on purpose: parsePHC
// rejects before argon2.IDKey is ever called, so the test proves the rejection
// without asking the machine to attempt the allocation it is guarding against.

// phc builds a PHC string with the given parameters and, crucially, a salt and
// key of exactly the lengths parsePHC requires.
//
// That detail is the whole point. The bound tests that already existed used a
// hand-written string with a four-byte salt — "$argon2id$v=19$m=4000000000,
// t=3,p=2$c2FsdA$a2V5" — so parsePHC rejected them on the salt-length check
// and never reached the parameter bounds. Every one of those bounds could be
// deleted with the suite green.
func phcFixture(t *testing.T, algo string, version, memory, iterations, parallelism int) string {
	t.Helper()
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, phc.SaltLen))
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, phc.KeyLen))
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", algo, version, memory, iterations, parallelism, salt, key)
}

// The bounds must not reject what Hash itself produces — the fixture above is
// only trustworthy if the real thing passes the same parser.
func TestParsePHC_acceptsWhatHashProduces(t *testing.T) {
	h, err := newMod(t).Hash("Correct-Horse-Battery-Staple-9")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, _, _, err := phc.Parse(h); err != nil {
		t.Fatalf("a hash this module produced must parse: %v", err)
	}
}

func TestVerify_wrongAlgorithmReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)

	// The fixture uses the phcFixture() helper, which gives a salt and key of the
	// exact lengths parsePHC requires. The four-byte salt the previous
	// fixture carried was what made the test green with the algorithm
	// check removed: parsePHC refused on salt length first and never
	// reached the algorithm. With valid salt and key, removing the
	// algorithm check lets the bcrypt-shaped hash pass into argon2.IDKey
	// and the test no longer catches the sabotage.
	wrongAlg := phcFixture(t, "bcrypt", argon2.Version, phc.MinMemory, 3, 1)

	_, err := mod.Verify("password", wrongAlg)
	if !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("expected password.ErrInvalidHash, got %v", err)
	}
}

// ---- parsePHC() -------------------------------------------------------------

func TestVerify_malformedStoredHashIsRejectedBeforeKeyDerivation(t *testing.T) {
	p := newMod(t)

	// If Verify accepted this hash, argon2.IDKey would try to allocate 4 TiB.
	// parsePHC must surface ErrInvalidHash instead.
	//
	// The salt and key are well formed on purpose, so the memory ceiling is
	// the only thing left that can refuse this. With the four-byte salt this
	// used to carry, the salt-length check refused it first and the test
	// stayed green with the ceiling deleted.
	malicious := phcFixture(t, "argon2id", argon2.Version, phc.MaxMemory+1, 3, 1)
	_, err := p.Verify("any-password-we-do-not-care", malicious)
	if !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash for malicious stored hash, got %v", err)
	}
}

func TestVerify_emptyKeySegmentRejectedNotPanic(t *testing.T) {
	p := newMod(t)

	// A truncated hash with an empty key segment reaches argon2.IDKey with
	// phc.KeyLen=0, which panics (nil dereference) and crashes the process.
	// parsePHC must reject it as password.ErrInvalidHash, never derive a key.
	cases := map[string]string{
		"empty key":  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$",
		"empty salt": "$argon2id$v=19$m=65536,t=3,p=2$$" + strings.Repeat("A", 43),
		"short key":  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$a2V5",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := p.Verify("any-password-we-do-not-care", h)
			if ok {
				t.Fatalf("%s: malformed hash must never verify true", name)
			}
			if !errors.Is(err, password.ErrInvalidHash) {
				t.Errorf("%s: expected password.ErrInvalidHash, got %v", name, err)
			}
		})
	}
}
