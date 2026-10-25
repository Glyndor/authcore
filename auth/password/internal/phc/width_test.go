package phc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
)

// A PHC parameter that does not fit its field must be refused, not wrapped.
// Until #451 the parser read every field at 64 bits and narrowed afterwards,
// so the range checks saw the wrapped value: m=4294975488 (2^32 + 8192) was
// read as 8192 and a hash carrying it verified.
//
// Each rejection below is paired with a value of the same field that fits the
// width, so a fixture refused for some other reason cannot pass as a width
// refusal. The fixtures come from phcFixture, which builds a salt and key of exactly
// the required lengths.

// widthRefusal is the strconv.ErrRange text the width check produces.
const widthRefusal = "value out of range"

// The symptom as a caller saw it: a real hash with one field widened past
// 2^32 or 2^8 verified the right password.
func TestVerify_refusesAHashWithAWrappedParameter(t *testing.T) {
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
		t.Fatalf("unmodified hash: ok=%v err=%v, want true, nil", ok, err)
	}
	for _, tc := range []struct{ from, to string }{
		{"m=8192", "m=4294975488"},
		{"t=1", "t=4294967297"},
		{"p=1", "p=257"},
	} {
		wrapped := replaceOnce(t, hash, tc.from, tc.to)
		ok, err := mod.Verify(pw, wrapped)
		if ok {
			t.Fatalf("%s: verified, want refused", tc.to)
		}
		if !errors.Is(err, password.ErrInvalidHash) || !strings.Contains(err.Error(), widthRefusal) {
			t.Fatalf("%s: %v, want ErrInvalidHash with the width refusal", tc.to, err)
		}
	}
}

func replaceOnce(t *testing.T, s, from, to string) string {
	t.Helper()
	if strings.Count(s, from) != 1 {
		t.Fatalf("fixture %q does not contain %q exactly once", s, from)
	}
	return strings.Replace(s, from, to, 1)
}
