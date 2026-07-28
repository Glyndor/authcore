package password

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
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
func phc(t *testing.T, algo string, version, memory, iterations, parallelism int) string {
	t.Helper()
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, saltLen))
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, keyLen))
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", algo, version, memory, iterations, parallelism, salt, key)
}

func TestParsePHC_boundsAndLabels(t *testing.T) {
	const okMem, okIter, okPar = minMemory, 3, 1

	for name, tc := range map[string]struct {
		hash string
		want string
	}{
		"a different algorithm is not silently treated as argon2id": {
			hash: phc(t, "argon2i", argon2.Version, okMem, okIter, okPar),
			want: "argon2id",
		},
		"a different argon2 version is refused": {
			hash: phc(t, "argon2id", argon2.Version+1, okMem, okIter, okPar),
			want: "version",
		},
		"memory below the floor is refused": {
			hash: phc(t, "argon2id", argon2.Version, minMemory-1, okIter, okPar),
			want: "memory",
		},
		"memory above the ceiling is refused — it is what Verify would allocate": {
			hash: phc(t, "argon2id", argon2.Version, maxMemory+1, okIter, okPar),
			want: "memory",
		},
		"zero iterations is refused": {
			hash: phc(t, "argon2id", argon2.Version, okMem, 0, okPar),
			want: "iterations",
		},
		"iterations above the ceiling is refused — it is what Verify would spend": {
			hash: phc(t, "argon2id", argon2.Version, okMem, maxIterations+1, okPar),
			want: "iterations",
		},
		"zero parallelism is refused": {
			hash: phc(t, "argon2id", argon2.Version, okMem, okIter, 0),
			want: "parallelism",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := parsePHC(tc.hash)
			if err == nil {
				t.Fatal("this hash string must be refused before any key derivation")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("refused for the wrong reason: want something about %q, got: %v", tc.want, err)
			}
		})
	}
}

// The bounds must not reject what Hash itself produces — the fixture above is
// only trustworthy if the real thing passes the same parser.
func TestParsePHC_acceptsWhatHashProduces(t *testing.T) {
	h, err := newMod(t).Hash("Correct-Horse-Battery-Staple-9")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, _, _, err := parsePHC(h); err != nil {
		t.Fatalf("a hash this module produced must parse: %v", err)
	}
}

// And the fixture itself has to be accepted when nothing is out of range,
// otherwise the rejections above prove nothing.
func TestParsePHC_acceptsTheFixtureWhenInRange(t *testing.T) {
	if _, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, minMemory, 3, 1)); err != nil {
		t.Fatalf("an in-range fixture must parse, or the bound tests are meaningless: %v", err)
	}
}
