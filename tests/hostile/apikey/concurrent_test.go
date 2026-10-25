package apikey_test

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Class: one module shared by many goroutines (run with -race), then extreme
// key strings handed to the parser.

func TestHostile_Concurrent_generateParseAndVerifyOnOneModule(t *testing.T) {
	m := newModule(t)
	const goroutines, each = 16, 250
	type pair struct{ key, id, hash string }
	all := make([][]pair, goroutines)

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				k, err := m.Generate()
				if err != nil {
					t.Error(err)
					return
				}
				id, err := m.ParseID(k.Key)
				if err != nil || id != k.ID {
					t.Errorf("ParseID = %q, %v; want %q", id, err, k.ID)
					return
				}
				if !m.Verify(k.Key, k.Hash) {
					t.Error("Verify refused a key just generated")
					return
				}
				all[g] = append(all[g], pair{k.Key, k.ID, k.Hash})
			}
		}()
	}
	wg.Wait()

	keys, ids, hashes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var flat []pair
	for _, list := range all {
		for _, p := range list {
			if keys[p.key] || ids[p.id] || hashes[p.hash] {
				t.Fatal("a key, id or hash repeated across goroutines")
			}
			keys[p.key], ids[p.id], hashes[p.hash] = true, true, true
			flat = append(flat, p)
		}
	}

	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := g; i < len(flat); i += 8 {
				own, other := flat[i], flat[(i+1)%len(flat)]
				if m.Verify(own.key, other.hash) || m.Verify(other.key, own.hash) {
					t.Error("a key verified against another key's hash")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Strings far larger than any key, shaped like one: refused by the parser in
// time proportional to their length, never by an allocation that dwarfs them.
func TestHostile_Parse_enormousStringsAreRefusedPromptly(t *testing.T) {
	m := newModule(t)
	g, _ := m.Generate()
	id := g.ID
	secret := g.Key[strings.LastIndex(g.Key, "_")+1:]
	for name, key := range map[string]string{
		"id a megabyte long":        "ak_" + strings.Repeat("a", 1<<20) + "_" + secret,
		"secret a megabyte long":    "ak_" + id + "_" + strings.Repeat("a", 1<<20),
		"thirty-two MiB of prefix":  strings.Repeat("a", 32<<20),
		"many separators":           "ak_" + strings.Repeat("_", 4<<20),
		"valid key then a megabyte": g.Key + strings.Repeat("0", 1<<20),
		"valid key then separators": g.Key + strings.Repeat("_a", 1<<19),
	} {
		start := time.Now()
		if got, err := m.ParseID(key); err == nil || got != "" {
			t.Errorf("%s: ParseID = %q, %v; want a refusal", name, got, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}
