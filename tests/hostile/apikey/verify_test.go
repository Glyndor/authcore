package apikey_test

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
)

// Verify compares the HMAC of the presented key with the stored hash, exactly.
// A hash that is a prefix of the right one, a re-cased one, or one with
// trailing bytes never matches, and neither does a key that is the right one
// with anything added or removed.
func TestHostile_Verify_exactMatchOnly(t *testing.T) {
	m := newModule(t)
	k, _ := m.Generate()
	other, _ := m.Generate()

	if !m.Verify(k.Key, k.Hash) {
		t.Fatal("control: the key does not verify against its own hash")
	}
	for name, stored := range map[string]string{
		"empty":            "",
		"prefix":           k.Hash[:len(k.Hash)-1],
		"extra char":       k.Hash + "0",
		"trailing NUL":     k.Hash + "\x00",
		"trailing newline": k.Hash + "\n",
		"leading space":    " " + k.Hash,
		"upper case":       strings.ToUpper(k.Hash),
		"another key":      other.Hash,
		"all zero":         strings.Repeat("0", len(k.Hash)),
		"the key itself":   k.Key,
		"doubled":          k.Hash + k.Hash,
	} {
		if m.Verify(k.Key, stored) {
			t.Errorf("stored hash %q verified", name)
		}
	}
	for name, key := range map[string]string{
		"empty":                 "",
		"truncated":             k.Key[:len(k.Key)-1],
		"extended":              k.Key + "0",
		"trailing newline":      k.Key + "\n",
		"leading space":         " " + k.Key,
		"upper case":            strings.ToUpper(k.Key),
		"another key":           other.Key,
		"same id, other secret": "ak_" + k.ID + "_" + strings.Repeat("0", 64),
		"other id, same secret": "ak_" + strings.Repeat("0", 32) + "_" + strings.TrimPrefix(k.Key, "ak_"+k.ID+"_"),
		"the hash":              k.Hash,
	} {
		if m.Verify(key, k.Hash) {
			t.Errorf("presented key %q verified", name)
		}
	}
}

// The hash of a key is a function of the deployment's pepper. A database dump
// from one deployment cannot be checked against keys of another, and a key
// that verifies in one does not in the other.
func TestHostile_Verify_hashIsBoundToThePepper(t *testing.T) {
	a, b := newModule(t), newModule(t)
	k, _ := a.Generate()
	if b.Verify(k.Key, k.Hash) {
		t.Fatal("a hash from another deployment verified")
	}
	hb, err := b.Hash(k.Key)
	if err != nil || hb == k.Hash {
		t.Fatalf("two deployments hashed one key to the same value (%v)", err)
	}
}

// The pepper keys the hash. One that is empty, short or long means the hash is
// either a bare SHA-256 anyone can compute or a key the module did not mean to
// use, so construction refuses all of them.
func TestHostile_Pepper_onlyA32ByteSecretIsAccepted(t *testing.T) {
	for name, pepper := range map[string][]byte{
		"nil":      nil,
		"empty":    {},
		"one byte": {1},
		"31 bytes": make([]byte, 31),
		"33 bytes": make([]byte, 33),
		"64 bytes": make([]byte, 64),
		"1 MiB":    make([]byte, 1<<20),
	} {
		_, err := apikey.New(newProviderWithPepper(t, pepper))
		if !errors.Is(err, apikey.ErrInvalidConfig) {
			t.Errorf("%s: apikey.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := apikey.New(newProviderWithPepper(t, make([]byte, 32))); err != nil {
		t.Errorf("control: a 32 byte pepper was refused: %v", err)
	}
}

// A module that New did not build has no pepper. It refuses to hash, verify
// or parse, instead of hashing under an empty key.
func TestHostile_Pepper_uninitialisedModuleProducesNothing(t *testing.T) {
	zero := &apikey.APIKey{}
	if k, err := zero.Generate(); k != nil || !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("Generate = %+v, %v", k, err)
	}
	if h, err := zero.Hash("ak_x"); h != "" || !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("Hash = %q, %v", h, err)
	}
	if zero.Verify("ak_x", "") {
		t.Error("Verify returned true on a zero value")
	}
	if id, err := zero.ParseID("ak_x"); id != "" || !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("ParseID = %q, %v", id, err)
	}
	var nilMod *apikey.APIKey
	if id, err := nilMod.ParseID("ak_x"); id != "" || !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("nil ParseID = %q, %v", id, err)
	}
}

// Keys are drawn fresh from the system's random source: a large batch has no
// repeated id, secret or hash, and every key has the full 128 and 256 bits.
func TestHostile_Generate_noCollisionsAcrossALargeBatch(t *testing.T) {
	m := newModule(t)
	ids, hashes, secrets := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := 0; i < 20000; i++ {
		k, err := m.Generate()
		if err != nil {
			t.Fatal(err)
		}
		secret := strings.TrimPrefix(k.Key, "ak_"+k.ID+"_")
		if ids[k.ID] || hashes[k.Hash] || secrets[secret] {
			t.Fatalf("collision after %d keys", i)
		}
		ids[k.ID], hashes[k.Hash], secrets[secret] = true, true, true
		if len(k.ID) != 32 || len(secret) != 64 || len(k.Hash) != 64 {
			t.Fatalf("id=%d secret=%d hash=%d characters", len(k.ID), len(secret), len(k.Hash))
		}
	}
}

// STATISTICAL PROPERTY, not a deterministic one.
//
// Verify takes the same time whether the stored hash matches or differs in its
// first or last byte. The comparison is between the HMAC of the presented key
// and the stored hash, and an adversary cannot choose that HMAC, so a timing
// signal here would be hard to use; the check guards against an early-exit
// comparison being introduced. The tolerance is a factor of two on medians of
// batches because nanosecond differences are below what a shared runner shows.
func TestHostile_Verify_comparisonTimeDoesNotDependOnWhereTheHashDiffers(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical timing check")
	}
	m := newModule(t)
	k, _ := m.Generate()
	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'a' {
			b[i] = 'b'
		} else {
			b[i] = 'a'
		}
		return string(b)
	}
	variants := map[string]string{
		"match":      k.Hash,
		"first byte": flip(k.Hash, 0),
		"last byte":  flip(k.Hash, len(k.Hash)-1),
	}
	const batches, perBatch = 9, 20000
	med := map[string]time.Duration{}
	times := map[string][]time.Duration{}
	for round := 0; round < batches; round++ {
		for name, stored := range variants {
			start := time.Now()
			for i := 0; i < perBatch; i++ {
				m.Verify(k.Key, stored)
			}
			times[name] = append(times[name], time.Since(start))
		}
	}
	for name, ts := range times {
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		med[name] = ts[len(ts)/2]
	}
	for _, name := range []string{"first byte", "last byte"} {
		ratio := float64(med[name]) / float64(med["match"])
		t.Logf("%s: median %v against %v for a match (ratio %.2f)", name, med[name], med["match"], ratio)
		if ratio < 0.5 || ratio > 2.0 {
			t.Errorf("%s: timing ratio %.2f is outside [0.5, 2.0]", name, ratio)
		}
	}
}
