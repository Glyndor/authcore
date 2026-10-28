// Package concurrent attacks the password module with many goroutines that
// share one instance.
package concurrent

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// Attacker: a login endpoint fed stored rows an adversary could write
// (corrupted, oversized, or asking for more than the module allows), next to
// honest rows, on one shared module. Forbidden effect: a hostile row changes
// the answer an honest row gets, panics, or leaves state behind (a different
// cost, a repeated salt) for the callers after it.
func TestHostile_Concurrent_hostileAndValidHashesDoNotTouchEachOther(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	good, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	p := hostiletest.Parts(t, good)

	type row struct {
		name    string
		hash    string
		pw      string
		wantOK  bool
		invalid bool // want ErrInvalidHash
	}
	rows := []row{
		{name: "valid, right password", hash: good, pw: hostiletest.Strong, wantOK: true},
		{name: "valid, wrong password", hash: good, pw: hostiletest.Strong + "x"},
		{name: "empty", hash: "", pw: hostiletest.Strong, invalid: true},
		{name: "garbage", hash: "not-a-hash", pw: hostiletest.Strong, invalid: true},
		{name: "one MiB of junk", hash: "$argon2id$" + strings.Repeat("A", 1<<20), pw: hostiletest.Strong, invalid: true},
		{name: "NUL in the middle", hash: good[:len(good)/2] + "\x00" + good[len(good)/2:], pw: hostiletest.Strong, invalid: true},
		{name: "truncated", hash: good[:len(good)-5], pw: hostiletest.Strong, invalid: true},
		{name: "memory above the ceiling", hash: hostiletest.Join("", "argon2id", "v=19", "m=4194304,t=1,p=1", p[4], p[5]), pw: hostiletest.Strong, invalid: true},
		{name: "passes above the ceiling", hash: hostiletest.Join("", "argon2id", "v=19", "m=8192,t=99,p=1", p[4], p[5]), pw: hostiletest.Strong, invalid: true},
		{name: "overflowing memory", hash: hostiletest.Join("", "argon2id", "v=19", "m=99999999999,t=1,p=1", p[4], p[5]), pw: hostiletest.Strong, invalid: true},
		{name: "other algorithm", hash: hostiletest.Join("", "argon2i", "v=19", "m=8192,t=1,p=1", p[4], p[5]), pw: hostiletest.Strong, invalid: true},
	}

	const workers, laps = 12, 40
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		mu      sync.Mutex
		salts   = map[string]bool{}
		hashErr error
	)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for lap := range laps {
				r := rows[(w+lap)%len(rows)]
				ok, err := m.Verify(r.pw, r.hash)
				switch {
				case r.invalid && (ok || !errors.Is(err, password.ErrInvalidHash)):
					t.Errorf("%s: Verify = %v, %v; want false, ErrInvalidHash", r.name, ok, err)
				case !r.invalid && (err != nil || ok != r.wantOK):
					t.Errorf("%s: Verify = %v, %v; want %v, nil", r.name, ok, err, r.wantOK)
				}
				if lap%8 != 0 {
					continue
				}
				fresh, err := m.Hash(hostiletest.Strong)
				mu.Lock()
				if err != nil {
					hashErr = err
				} else if salt := strings.Split(fresh, "$")[4]; salts[salt] {
					t.Errorf("two concurrent Hash calls produced the salt %s", salt)
				} else {
					salts[salt] = true
				}
				mu.Unlock()
				if ok, err := m.Verify(hostiletest.Strong, fresh); err != nil || !ok {
					t.Errorf("a hash produced under load does not verify: %v, %v", ok, err)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if hashErr != nil {
		t.Fatalf("Hash under load: %v", hashErr)
	}

	// Nothing the hostile rows did is left behind: the cost parameters are the
	// configured ones and the original row still answers correctly.
	after, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hostiletest.Parts(t, after)[3], hostiletest.Parts(t, good)[3]; got != want {
		t.Fatalf("cost parameters after the storm = %q, before = %q", got, want)
	}
	if ok, err := m.Verify(hostiletest.Strong, good); err != nil || !ok {
		t.Fatalf("original hash after the storm: %v, %v", ok, err)
	}
}
