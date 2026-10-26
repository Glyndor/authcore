package keyspace

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// keyTable is the api_keys table: id to hash, one atomic statement at a time.
type keyTable struct {
	mu   sync.Mutex
	rows map[string]string
}

func (k *keyTable) insert(id, hash string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, taken := k.rows[id]; taken {
		return false
	}
	k.rows[id] = hash
	return true
}

func (k *keyTable) get(id string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	h, ok := k.rows[id]
	return h, ok
}

func (k *keyTable) remove(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.rows, id)
}

// authenticate is the documented request path: parse the id out of the key,
// find the row by id, verify the whole key against the stored hash.
func authenticate(m *apikey.APIKey, table *keyTable, presented string) (string, bool) {
	id, err := m.ParseID(presented)
	if err != nil {
		return "", false
	}
	stored, ok := table.get(id)
	if !ok || !m.Verify(presented, stored) {
		return "", false
	}
	return id, true
}

// Many keys, mutated every way an attacker can without the secret: the genuine
// one authenticates as its own row, no mutation authenticates as anything.
func TestE2E_Keyspace_aMutatedAPIKeyAuthenticatesAsNothing(t *testing.T) {
	m := hostiletest.NewEnv(t).APIKey(t)
	table := &keyTable{rows: map[string]string{}}
	keys := make([]*apikey.GeneratedKey, 8)
	for i := range keys {
		g, err := m.Generate()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = g
		if !table.insert(g.ID, g.Hash) {
			t.Fatal("generated an id that is already taken")
		}
	}
	for i, g := range keys {
		if id, ok := authenticate(m, table, g.Key); !ok || id != g.ID {
			t.Fatalf("genuine key %d = %q, %v", i, id, ok)
		}
		other := keys[(i+1)%len(keys)]
		idPart, secretPart := splitKey(t, g.Key)
		_, otherSecret := splitKey(t, other.Key)
		mutations := map[string]string{
			"last char":        g.Key[:len(g.Key)-1] + flip(g.Key[len(g.Key)-1]),
			"secret of other":  idPart + otherSecret,
			"id of other":      strings.Replace(g.Key, g.ID, other.ID, 1),
			"truncated":        g.Key[:len(g.Key)-1],
			"extended":         g.Key + "0",
			"upper case":       strings.ToUpper(g.Key),
			"id only":          idPart,
			"secret only":      secretPart,
			"trailing newline": g.Key + "\n",
			"leading space":    " " + g.Key,
			"empty":            "",
		}
		for name, v := range mutations {
			if id, ok := authenticate(m, table, v); ok {
				t.Errorf("key %d mutated by %q authenticated as %q", i, name, id)
			}
		}
	}
}

// splitKey returns the id and secret parts of "prefix_id_secret" with prefix.
func splitKey(t *testing.T, key string) (string, string) {
	t.Helper()
	parts := strings.Split(key, "_")
	if len(parts) != 3 {
		t.Fatalf("key %q has %d parts, want 3", key, len(parts))
	}
	return parts[0] + "_" + parts[1] + "_", parts[2]
}

func flip(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

// Revocation is a delete: the key stops authenticating on the next request, and
// the hash that is left over matches nobody else.
func TestE2E_Keyspace_revokingARowEndsTheKey(t *testing.T) {
	m := hostiletest.NewEnv(t).APIKey(t)
	table := &keyTable{rows: map[string]string{}}
	a, _ := m.Generate()
	b, _ := m.Generate()
	table.insert(a.ID, a.Hash)
	table.insert(b.ID, b.Hash)
	table.remove(a.ID)
	if _, ok := authenticate(m, table, a.Key); ok {
		t.Error("revoked key authenticated")
	}
	if _, ok := authenticate(m, table, b.Key); !ok {
		t.Error("revoking one key ended another")
	}
	// Re-inserting a's hash under b's id must not let a's key in as b: the id
	// inside the presented key picks the row.
	table.insert(a.ID, b.Hash)
	if _, ok := authenticate(m, table, a.Key); ok {
		t.Error("a key authenticated against a row holding another key's hash")
	}
}

// Generation and verification under load: ids never collide, every key verifies
// against its own hash and no other, and the table never loses a row.
func TestE2E_Keyspace_concurrentGenerationAndVerification(t *testing.T) {
	m := hostiletest.NewEnv(t).APIKey(t)
	table := &keyTable{rows: map[string]string{}}
	const workers, perWorker = 16, 64
	var (
		wg        sync.WaitGroup
		collision atomic.Int64
		bad       atomic.Int64
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				g, err := m.Generate()
				if err != nil {
					bad.Add(1)
					return
				}
				if !table.insert(g.ID, g.Hash) {
					collision.Add(1)
				}
				if id, ok := authenticate(m, table, g.Key); !ok || id != g.ID {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if collision.Load() != 0 || bad.Load() != 0 {
		t.Fatalf("collisions=%d failures=%d, want 0 and 0", collision.Load(), bad.Load())
	}
	if len(table.rows) != workers*perWorker {
		t.Errorf("table holds %d rows, want %d", len(table.rows), workers*perWorker)
	}
}
