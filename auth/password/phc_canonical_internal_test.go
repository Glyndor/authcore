package password

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// parsePHC accepts only the exact string Hash writes. Before #456 the base64
// decoder skipped line breaks and ignored the unused bits of the last
// character, and strconv took leading zeros, so one stored hash had several
// spellings that all verified. Each case below changes exactly one of those
// things in an otherwise valid hash and checks that the refusal is the
// canonical-form one, not a length or parse error.

const canonicalRefusal = "not in canonical form"

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

func TestParsePHC_refusesNonCanonicalSpellings(t *testing.T) {
	valid := phc(t, "argon2id", 19, minMemory, 3, 1)
	parts := strings.Split(valid, "$")
	salt, key := parts[4], parts[5]

	for name, hash := range map[string]string{
		"line feed in the key":        withSegment(t, valid, 5, key[:10]+"\n"+key[10:]),
		"carriage return in the salt": withSegment(t, valid, 4, salt[:5]+"\r"+salt[5:]),
		"unused bits set in the salt": withSegment(t, valid, 4, flipUnusedBits(t, salt, saltLen)),
		"unused bits set in the key":  withSegment(t, valid, 5, flipUnusedBits(t, key, keyLen)),
		"leading zero in memory":      strings.Replace(valid, "m="+itoa(minMemory), "m=0"+itoa(minMemory), 1),
		"leading zero in version":     strings.Replace(valid, "v=19", "v=019", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if hash == valid {
				t.Fatal("fixture is identical to the valid hash")
			}
			_, _, _, err := parsePHC(hash)
			if !errors.Is(err, ErrInvalidHash) || !strings.Contains(err.Error(), canonicalRefusal) {
				t.Fatalf("parsePHC(%q) = %v, want ErrInvalidHash %q", hash, err, canonicalRefusal)
			}
		})
	}
}

// The acceptance side: the string Hash writes parses, and Verify still works
// on it end to end.
func TestParsePHC_acceptsWhatEncodePHCWrites(t *testing.T) {
	valid := phc(t, "argon2id", 19, minMemory, 3, 1)
	cfg, salt, key, err := parsePHC(valid)
	if err != nil {
		t.Fatalf("parsePHC(valid) = %v", err)
	}
	if got := encodePHC(cfg, salt, key); got != valid {
		t.Fatalf("encodePHC round trip:\n got  %q\n want %q", got, valid)
	}
}

func TestVerify_refusesASecondSpellingOfAHash(t *testing.T) {
	mod, err := New(fakeProvider{}, Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	const pw = "Correct-Horse-Battery-9"
	hash, err := mod.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := mod.Verify(pw, hash); !ok || err != nil {
		t.Fatalf("canonical hash: ok=%v err=%v, want true, nil", ok, err)
	}
	key := strings.Split(hash, "$")[5]
	respelled := withSegment(t, hash, 5, key[:20]+"\n"+key[20:])
	ok, err := mod.Verify(pw, respelled)
	if ok || !errors.Is(err, ErrInvalidHash) || !strings.Contains(err.Error(), canonicalRefusal) {
		t.Fatalf("respelled hash: ok=%v err=%v, want false with %q", ok, err, canonicalRefusal)
	}
}
