package binding

import (
	"bytes"
	"testing"
)

var secret = bytes.Repeat([]byte{9}, 32)

func TestHash_isDeterministic64CharHex(t *testing.T) {
	got := Hash(secret, "reset", "alice@example.com", "tok")
	if got != Hash(secret, "reset", "alice@example.com", "tok") {
		t.Error("the same inputs gave two hashes")
	}
	if len(got) != 64 {
		t.Errorf("hash is %d characters, want 64", len(got))
	}
}

func TestHash_changesWithEverythingItBinds(t *testing.T) {
	base := Hash(secret, "reset", "alice", "tok")
	for name, got := range map[string]string{
		"secret":  Hash(bytes.Repeat([]byte{8}, 32), "reset", "alice", "tok"),
		"purpose": Hash(secret, "activate", "alice", "tok"),
		"subject": Hash(secret, "reset", "bob", "tok"),
		"token":   Hash(secret, "reset", "alice", "tok2"),
	} {
		if got == base {
			t.Errorf("changing the %s kept the hash", name)
		}
	}
}

func TestHash_lengthPrefixKeepsFieldBoundaries(t *testing.T) {
	pairs := [][2][3]string{
		{{"a", "bc", "t"}, {"ab", "c", "t"}},
		{{"a\x00b", "c", "t"}, {"a", "b\x00c", "t"}},
		{{"p", "s", "tok"}, {"p", "st", "ok"}},
	}
	for _, p := range pairs {
		if Hash(secret, p[0][0], p[0][1], p[0][2]) == Hash(secret, p[1][0], p[1][1], p[1][2]) {
			t.Errorf("%q and %q collide", p[0], p[1])
		}
	}
}
