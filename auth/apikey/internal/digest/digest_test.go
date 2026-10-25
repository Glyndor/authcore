package digest

import (
	"bytes"
	"testing"
)

func TestHash_isDeterministic64CharHexKeyedBySecretAndKey(t *testing.T) {
	secret := bytes.Repeat([]byte{3}, 32)
	got := Hash(secret, "ak_key")
	if len(got) != 64 {
		t.Errorf("hash is %d characters, want 64", len(got))
	}
	if got != Hash(secret, "ak_key") {
		t.Error("the same inputs gave two hashes")
	}
	if got == Hash(secret, "ak_key2") {
		t.Error("another key kept the hash")
	}
	if got == Hash(bytes.Repeat([]byte{4}, 32), "ak_key") {
		t.Error("another secret kept the hash")
	}
}
