package blind

import (
	"bytes"
	"testing"
)

func TestIndex_isDeterministicFixedSizeHex(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	got := Index(key, []byte("email"), "alice@example.com")
	if got != Index(key, []byte("email"), "alice@example.com") {
		t.Error("the same inputs gave two indexes")
	}
	if len(got) != 64 {
		t.Errorf("index is %d characters, want 64", len(got))
	}
	for _, c := range got {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("index %q is not lowercase hex", got)
		}
	}
}

func TestIndex_separatesKeyContextAndValue(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	other := bytes.Repeat([]byte{8}, 32)
	base := Index(key, []byte("email"), "alice")
	for name, got := range map[string]string{
		"another key":     Index(other, []byte("email"), "alice"),
		"another context": Index(key, []byte("phone"), "alice"),
		"another value":   Index(key, []byte("email"), "bob"),
	} {
		if got == base {
			t.Errorf("%s produced the same index", name)
		}
	}
}

// The length prefix keeps the boundary between context and value, which a
// plain concatenation or a separator byte does not.
func TestIndex_noCollisionAcrossTheContextValueBoundary(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	pairs := [][2][2]string{
		{{"a", "bc"}, {"ab", "c"}},
		{{"email", "user@x"}, {"emailuser", "@x"}},
		{{"a\x00b", "c"}, {"a", "b\x00c"}},
	}
	for _, p := range pairs {
		left := Index(key, []byte(p[0][0]), p[0][1])
		right := Index(key, []byte(p[1][0]), p[1][1])
		if left == right {
			t.Errorf("%q and %q collide", p[0], p[1])
		}
	}
}
