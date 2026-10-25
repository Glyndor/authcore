package phc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
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

func TestVerify_refusesASecondSpellingOfAHash(t *testing.T) {
	mod, err := password.New(fakeProvider{}, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
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
	if ok || !errors.Is(err, password.ErrInvalidHash) || !strings.Contains(err.Error(), canonicalRefusal) {
		t.Fatalf("respelled hash: ok=%v err=%v, want false with %q", ok, err, canonicalRefusal)
	}
}
