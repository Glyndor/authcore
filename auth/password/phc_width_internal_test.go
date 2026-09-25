package password

import (
	"errors"
	"strings"
	"testing"
)

// A PHC parameter that does not fit its field must be refused, not wrapped.
// Until #451 the parser read every field at 64 bits and narrowed afterwards,
// so the range checks saw the wrapped value: m=4294975488 (2^32 + 8192) was
// read as 8192 and a hash carrying it verified.
//
// Each rejection below is paired with a value of the same field that fits the
// width, so a fixture refused for some other reason cannot pass as a width
// refusal. The fixtures come from phc, which builds a salt and key of exactly
// the required lengths.

// widthRefusal is the strconv.ErrRange text the width check produces.
const widthRefusal = "value out of range"

func TestParsePHC_refusesValuesWiderThanTheirField(t *testing.T) {
	valid := phc(t, "argon2id", 19, minMemory, 3, 1)
	for name, tc := range map[string]struct{ from, to string }{
		"version 2^32+19":    {"v=19", "v=4294967315"},
		"memory 2^32+8192":   {"m=" + itoa(minMemory), "m=4294975488"},
		"iterations 2^32+3":  {"t=3", "t=4294967299"},
		"parallelism 2^8+1":  {"p=1", "p=257"},
		"parallelism 2^16+1": {"p=1", "p=65537"},
	} {
		t.Run(name, func(t *testing.T) {
			hash := replaceOnce(t, valid, tc.from, tc.to)
			_, _, _, err := parsePHC(hash)
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("parsePHC(%q) = %v, want ErrInvalidHash", hash, err)
			}
			if !strings.Contains(err.Error(), widthRefusal) {
				t.Fatalf("parsePHC(%q) = %v, want the width refusal %q", hash, err, widthRefusal)
			}
		})
	}
}

// The largest value each field can hold is not refused for width. Parallelism
// has no upper bound of its own, so 255 parses; the others are refused by the
// range check that follows, which names the parameter instead.
func TestParsePHC_acceptsTheWidestValueEachFieldHolds(t *testing.T) {
	valid := phc(t, "argon2id", 19, minMemory, 3, 1)

	cfg, _, _, err := parsePHC(replaceOnce(t, valid, "p=1", "p=255"))
	if err != nil {
		t.Fatalf("p=255: %v, want accepted", err)
	}
	if cfg.Parallelism != 255 {
		t.Fatalf("p=255 parsed as %d", cfg.Parallelism)
	}

	for name, tc := range map[string]struct{ from, to, reason string }{
		"version":    {"v=19", "v=4294967295", "unsupported Argon2 version"},
		"memory":     {"m=" + itoa(minMemory), "m=4294967295", "memory parameter out of range"},
		"iterations": {"t=3", "t=4294967295", "iterations parameter out of range"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := parsePHC(replaceOnce(t, valid, tc.from, tc.to))
			if !errors.Is(err, ErrInvalidHash) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("%s: %v, want ErrInvalidHash naming %q", tc.to, err, tc.reason)
			}
			if strings.Contains(err.Error(), widthRefusal) {
				t.Fatalf("%s fits the field and was refused for width: %v", tc.to, err)
			}
		})
	}
}

// The symptom as a caller saw it: a real hash with one field widened past
// 2^32 or 2^8 verified the right password.
func TestVerify_refusesAHashWithAWrappedParameter(t *testing.T) {
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
		if !errors.Is(err, ErrInvalidHash) || !strings.Contains(err.Error(), widthRefusal) {
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
