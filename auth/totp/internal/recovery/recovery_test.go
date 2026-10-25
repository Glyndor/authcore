package recovery

import (
	"regexp"
	"testing"
)

var shape = regexp.MustCompile(`^[A-Z2-7]{8}-[A-Z2-7]{8}$`)

func TestNew_hasTheDisplayShape(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !shape.MatchString(a) || !shape.MatchString(b) {
		t.Fatalf("codes %q, %q do not match %s", a, b, shape)
	}
	if a == b {
		t.Fatalf("two codes are equal: %q", a)
	}
}

func TestFormat(t *testing.T) {
	if got := Format("ABCD1234EFGH5678"); got != "ABCD1234-EFGH5678" {
		t.Errorf("Format = %q", got)
	}
	for _, s := range []string{"", "ABCD", "ABCD1234EFGH56789"} {
		if got := Format(s); got != s {
			t.Errorf("Format(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"abcd1234-efgh5678": "ABCD1234EFGH5678",
		"ABCD 1234 EFGH":    "ABCD1234EFGH",
		" - ":               "",
		"":                  "",
		"Zz9":               "ZZ9",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// Hash is keyed and normalises first: every spelling of one code hashes alike,
// a different key or code does not.
func TestHash(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	h := Hash(key, "ABCD1234-EFGH5678")
	if len(h) != 64 {
		t.Fatalf("digest length = %d, want 64 hex characters", len(h))
	}
	for _, spelling := range []string{"abcd1234efgh5678", "abcd 1234 efgh 5678", "ABCD1234EFGH5678"} {
		if Hash(key, spelling) != h {
			t.Errorf("Hash(%q) differs from the canonical spelling", spelling)
		}
	}
	if Hash(key, "ABCD1234-EFGH5679") == h {
		t.Error("a different code hashed alike")
	}
	if Hash([]byte("another key another key another"), "ABCD1234-EFGH5678") == h {
		t.Error("a different key hashed alike")
	}
}
