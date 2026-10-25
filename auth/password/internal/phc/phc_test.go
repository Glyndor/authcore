package phc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// itoa formats n in base 10.
func itoa(n int) string { return strconv.Itoa(n) }

// fixture builds a PHC string with the given parameters and, crucially, a salt
// and key of exactly the lengths Parse requires.
//
// That detail is the whole point. Bound tests that used a hand-written string
// with a four-byte salt, such as "$argon2id$v=19$m=4000000000,t=3,p=2$c2FsdA$a2V5",
// were refused on the salt-length check and never reached the parameter
// bounds, so every one of those bounds could be deleted with the suite green.
func fixture(t *testing.T, algo string, version, memory, iterations, parallelism int) string {
	t.Helper()
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, SaltLen))
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, KeyLen))
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", algo, version, memory, iterations, parallelism, salt, key)
}

// withSegment returns hash with its dollar-separated segment i replaced.
func withSegment(t *testing.T, hash string, i int, seg string) string {
	t.Helper()
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("fixture %q is not a six-segment PHC string", hash)
	}
	parts[i] = seg
	return strings.Join(parts, "$")
}

// flipUnusedBits returns s, the unpadded base64 of n bytes, with the last
// character changed so that it decodes to the same bytes. It fails the test if
// n leaves no unused bits, because then the fixture would test nothing.
func flipUnusedBits(t *testing.T, s string, n int) string {
	t.Helper()
	if (n*8)%6 == 0 {
		t.Fatalf("%d bytes leave no unused bits in the last base64 character", n)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	flipped := s[:len(s)-1] + string(alphabet[last|1])
	a, errA := base64.RawStdEncoding.DecodeString(s)
	b, errB := base64.RawStdEncoding.DecodeString(flipped)
	if errA != nil || errB != nil || string(a) != string(b) || flipped == s {
		t.Fatalf("fixture: %q and %q do not decode to the same bytes", s, flipped)
	}
	return flipped
}

func replaceOnce(t *testing.T, s, from, to string) string {
	t.Helper()
	if strings.Count(s, from) != 1 {
		t.Fatalf("fixture %q does not contain %q exactly once", s, from)
	}
	return strings.Replace(s, from, to, 1)
}

// Verify derives the key with the parameters carried inside the stored hash,
// so a stored string decides how much memory and time the verification costs.
// The bounds in Parse are the only thing standing between a hostile or
// corrupted row and a 16 GiB allocation on the next login attempt. These
// assert at Parse because it rejects before argon2.IDKey is ever called.
func TestParse_boundsAndLabels(t *testing.T) {
	const okMem, okIter, okPar = MinMemory, 3, 1

	for name, tc := range map[string]struct {
		hash string
		want string
	}{
		"a different algorithm is not silently treated as argon2id": {
			hash: fixture(t, "argon2i", argon2.Version, okMem, okIter, okPar),
			want: "argon2id",
		},
		"a different argon2 version is refused": {
			hash: fixture(t, "argon2id", argon2.Version+1, okMem, okIter, okPar),
			want: "version",
		},
		"memory below the floor is refused": {
			hash: fixture(t, "argon2id", argon2.Version, MinMemory-1, okIter, okPar),
			want: "memory",
		},
		"memory above the ceiling is refused, it is what Verify would allocate": {
			hash: fixture(t, "argon2id", argon2.Version, MaxMemory+1, okIter, okPar),
			want: "memory",
		},
		"zero iterations is refused": {
			hash: fixture(t, "argon2id", argon2.Version, okMem, 0, okPar),
			want: "iterations",
		},
		"iterations above the ceiling is refused, it is what Verify would spend": {
			hash: fixture(t, "argon2id", argon2.Version, okMem, MaxIterations+1, okPar),
			want: "iterations",
		},
		"zero parallelism is refused": {
			hash: fixture(t, "argon2id", argon2.Version, okMem, okIter, 0),
			want: "parallelism",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := Parse(tc.hash)
			if err == nil {
				t.Fatal("this hash string must be refused before any key derivation")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("refusal does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("refused for the wrong reason: want something about %q, got: %v", tc.want, err)
			}
		})
	}
}

// The fixture itself has to be accepted when nothing is out of range,
// otherwise the rejections above prove nothing.
func TestParse_acceptsTheFixtureWhenInRange(t *testing.T) {
	if _, _, _, err := Parse(fixture(t, "argon2id", argon2.Version, MinMemory, 3, 1)); err != nil {
		t.Fatalf("an in-range fixture must parse, or the bound tests are meaningless: %v", err)
	}
}

func TestParse_malformedShapes(t *testing.T) {
	for name, h := range map[string]string{
		"wrong segment count":        "$argon2id$v=19$m=65536,t=3,p=2$onlyfour",
		"unparsable version":         "$argon2id$v=abc$m=65536,t=3,p=2$c2FsdA$a2V5",
		"unparsable params":          "$argon2id$v=19$invalid$c2FsdA$a2V5",
		"invalid base64 salt":        "$argon2id$v=19$m=65536,t=3,p=2$!!!notbase64!!!$a2V5",
		"invalid base64 key":         "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!notbase64!!!",
		"text before the dollar":     "junk" + fixture(t, "argon2id", argon2.Version, MinMemory, 3, 1),
		"empty key":                  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$",
		"empty salt":                 "$argon2id$v=19$m=65536,t=3,p=2$$" + strings.Repeat("A", 43),
		"short key":                  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$a2V5",
		"short salt":                 fixtureWithSalt(t, "c2FsdA"),
		"bare label":                 strings.Replace(fixture(t, "argon2id", 19, MinMemory, 3, 1), "m="+itoa(MinMemory), "m", 1),
		"empty value":                strings.Replace(fixture(t, "argon2id", 19, MinMemory, 3, 1), "m="+itoa(MinMemory), "m=", 1),
		"two parameter fields":       strings.Replace(fixture(t, "argon2id", 19, MinMemory, 3, 1), ",p=1", "", 1),
		"memory with trailing text":  strings.Replace(fixture(t, "argon2id", 19, MinMemory, 3, 1), "m="+itoa(MinMemory), "m="+itoa(MinMemory)+"junk", 1),
		"version with trailing text": strings.Replace(fixture(t, "argon2id", 19, MinMemory, 3, 1), "v=19", "v=19junk", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := Parse(h); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) = %v, want ErrInvalid", h, err)
			}
		})
	}
}

func fixtureWithSalt(t *testing.T, salt string) string {
	t.Helper()
	return withSegment(t, fixture(t, "argon2id", argon2.Version, MinMemory, 3, 1), 4, salt)
}

// Parse accepts only the exact string Encode writes. Before #456 the base64
// decoder skipped line breaks and ignored the unused bits of the last
// character, and strconv took leading zeros, so one stored hash had several
// spellings that all verified. Each case changes exactly one of those things in
// an otherwise valid hash and checks that the refusal is the canonical-form
// one, not a length or parse error.
const canonicalRefusal = "not in canonical form"

func TestParse_refusesNonCanonicalSpellings(t *testing.T) {
	valid := fixture(t, "argon2id", 19, MinMemory, 3, 1)
	parts := strings.Split(valid, "$")
	salt, key := parts[4], parts[5]

	for name, hash := range map[string]string{
		"line feed in the key":        withSegment(t, valid, 5, key[:10]+"\n"+key[10:]),
		"carriage return in the salt": withSegment(t, valid, 4, salt[:5]+"\r"+salt[5:]),
		"unused bits set in the salt": withSegment(t, valid, 4, flipUnusedBits(t, salt, SaltLen)),
		"unused bits set in the key":  withSegment(t, valid, 5, flipUnusedBits(t, key, KeyLen)),
		"leading zero in memory":      strings.Replace(valid, "m="+itoa(MinMemory), "m=0"+itoa(MinMemory), 1),
		"leading zero in version":     strings.Replace(valid, "v=19", "v=019", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if hash == valid {
				t.Fatal("fixture is identical to the valid hash")
			}
			_, _, _, err := Parse(hash)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), canonicalRefusal) {
				t.Fatalf("Parse(%q) = %v, want ErrInvalid %q", hash, err, canonicalRefusal)
			}
		})
	}
}

// The acceptance side: the string Encode writes parses back to the same value.
func TestParse_acceptsWhatEncodeWrites(t *testing.T) {
	valid := fixture(t, "argon2id", 19, MinMemory, 3, 1)
	p, salt, key, err := Parse(valid)
	if err != nil {
		t.Fatalf("Parse(valid) = %v", err)
	}
	if p != (Params{Memory: MinMemory, Iterations: 3, Parallelism: 1}) {
		t.Fatalf("Parse params = %+v", p)
	}
	if got := Encode(p, salt, key); got != valid {
		t.Fatalf("Encode round trip:\n got  %q\n want %q", got, valid)
	}
}

// A PHC parameter that does not fit its field must be refused, not wrapped.
// Until #451 the parser read every field at 64 bits and narrowed afterwards,
// so the range checks saw the wrapped value: m=4294975488 (2^32 + 8192) was
// read as 8192 and a hash carrying it verified.
//
// widthRefusal is the strconv.ErrRange text the width check produces.
const widthRefusal = "value out of range"

func TestParse_refusesValuesWiderThanTheirField(t *testing.T) {
	valid := fixture(t, "argon2id", 19, MinMemory, 3, 1)
	for name, tc := range map[string]struct{ from, to string }{
		"version 2^32+19":    {"v=19", "v=4294967315"},
		"memory 2^32+8192":   {"m=" + itoa(MinMemory), "m=4294975488"},
		"iterations 2^32+3":  {"t=3", "t=4294967299"},
		"parallelism 2^8+1":  {"p=1", "p=257"},
		"parallelism 2^16+1": {"p=1", "p=65537"},
	} {
		t.Run(name, func(t *testing.T) {
			hash := replaceOnce(t, valid, tc.from, tc.to)
			_, _, _, err := Parse(hash)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) = %v, want ErrInvalid", hash, err)
			}
			if !strings.Contains(err.Error(), widthRefusal) {
				t.Fatalf("Parse(%q) = %v, want the width refusal %q", hash, err, widthRefusal)
			}
		})
	}
}

// The largest value each field can hold is not refused for width. Parallelism
// has no upper bound of its own, so 255 parses; the others are refused by the
// range check that follows, which names the parameter instead.
func TestParse_acceptsTheWidestValueEachFieldHolds(t *testing.T) {
	valid := fixture(t, "argon2id", 19, MinMemory, 3, 1)

	p, _, _, err := Parse(replaceOnce(t, valid, "p=1", "p=255"))
	if err != nil {
		t.Fatalf("p=255: %v, want accepted", err)
	}
	if p.Parallelism != 255 {
		t.Fatalf("p=255 parsed as %d", p.Parallelism)
	}

	for name, tc := range map[string]struct{ from, to, reason string }{
		"version":    {"v=19", "v=4294967295", "unsupported Argon2 version"},
		"memory":     {"m=" + itoa(MinMemory), "m=4294967295", "memory parameter out of range"},
		"iterations": {"t=3", "t=4294967295", "iterations parameter out of range"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := Parse(replaceOnce(t, valid, tc.from, tc.to))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("%s: %v, want ErrInvalid naming %q", tc.to, err, tc.reason)
			}
			if strings.Contains(err.Error(), widthRefusal) {
				t.Fatalf("%s fits the field and was refused for width: %v", tc.to, err)
			}
		})
	}
}
