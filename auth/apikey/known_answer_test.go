package apikey_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
)

// Known answer: the storage hash is HMAC-SHA256 of the presented key under
// the refresh secret, hex encoded. newMod's secret is the fixed
// "0123456789abcdef0123456789abcdef"; the expected value was computed outside
// Go. A change here silently invalidates every stored API-key hash.
func TestHash_knownAnswer(t *testing.T) {
	m := newMod(t)
	got, err := m.Hash("ak_" + strings.Repeat("0", 32) + "_" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	const want = "04c0c76b2ab87102b22375ad2536905141a65a59adf51988e41564172a08e8f8"
	if got != want {
		t.Fatalf("Hash = %s, want %s: the stored-hash format changed", got, want)
	}
}

// A zero-value module must not hash: the digest under the empty key is one
// anyone can compute. Generate and Verify were pinned; Hash was not.
func TestZeroValue_HashFails(t *testing.T) {
	var zero apikey.APIKey
	hash, err := zero.Hash("ak_" + strings.Repeat("0", 32) + "_" + strings.Repeat("1", 64))
	if !errors.Is(err, apikey.ErrNotInitialised) || hash != "" {
		t.Fatalf("Hash on a zero value = %q, %v; want \"\", ErrNotInitialised", hash, err)
	}
}
