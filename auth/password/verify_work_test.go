package password

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// accepts reports whether a module configured with cfg lets a stored hash with
// cost p through to key derivation, by the same three comparisons Verify makes.
func accepts(cfg Config, p phc.Params) bool {
	c := applyDefaults(cfg).verifyCeiling()
	w := applyDefaults(cfg).verifyWorkCeiling()
	return p.Memory <= c.Memory && p.Iterations <= c.Iterations && p.Parallelism <= c.Parallelism &&
		uint64(p.Memory)*uint64(p.Iterations) <= w
}

// Every profile the library or a standard recommends keeps verifying under the
// module configured with that same profile, and the default module keeps
// verifying every profile that fits a 1 GiB hash. The two RFC 9106 profiles
// and the OWASP rows are the ones published when this was written.
func TestVerifyAcceptsTheRecommendedProfiles(t *testing.T) {
	profiles := []struct {
		name        string
		m, t, p     uint32
		defaultOnly bool // false: only a module configured with it verifies it
	}{
		{"library default", 64 * 1024, 3, 2, true},
		{"OWASP m=47104 t=1 p=1", 47104, 1, 1, true},
		{"OWASP m=19456 t=2 p=1", 19456, 2, 1, true},
		{"OWASP m=12288 t=3 p=1", 12288, 3, 1, true},
		{"OWASP m=9216 t=4 p=1", 9216, 4, 1, true},
		{"RFC 9106 second, 64 MiB t=3 p=4", 64 * 1024, 3, 4, true},
		{"RFC 9106 first, 2 GiB t=1 p=4", 2 * 1024 * 1024, 1, 4, false},
	}
	for _, pr := range profiles {
		p := phc.Params{Memory: pr.m, Iterations: pr.t, Parallelism: uint8(pr.p)}
		if pr.defaultOnly && !accepts(DefaultConfig(), p) {
			t.Errorf("%s: the default module refuses it", pr.name)
		}
		own := Config{Memory: pr.m, Iterations: pr.t, Parallelism: uint8(pr.p)}
		if !accepts(own, p) {
			t.Errorf("%s: a module configured with it refuses its own hash", pr.name)
		}
	}
}

// The worst hash the default module derives a key for is the product cap:
// 1 GiB for 4 passes. One more pass, or the 20 the factors alone allow, is
// refused. On the machine this was measured on the first costs about 3.7 s and
// 1 GiB of RSS, the second about 13 s.
func TestVerifyWorkCeilingTable(t *testing.T) {
	def := DefaultConfig()
	for _, tc := range []struct {
		name string
		p    phc.Params
		want bool
	}{
		{"1 GiB x 4 passes, at the cap", phc.Params{Memory: 1 << 20, Iterations: 4, Parallelism: 16}, true},
		{"1 GiB x 5 passes, one pass over", phc.Params{Memory: 1 << 20, Iterations: 5, Parallelism: 16}, false},
		{"1 GiB x 20 passes", phc.Params{Memory: 1 << 20, Iterations: 20, Parallelism: 16}, false},
		{"512 MiB x 8 passes, at the cap", phc.Params{Memory: 1 << 19, Iterations: 8, Parallelism: 16}, true},
		{"512 MiB x 9 passes", phc.Params{Memory: 1 << 19, Iterations: 9, Parallelism: 16}, false},
		{"8 MiB x 20 passes", phc.Params{Memory: phc.MinMemory, Iterations: 20, Parallelism: 1}, true},
		{"2 GiB x 1 pass, over the memory ceiling", phc.Params{Memory: 1 << 21, Iterations: 1, Parallelism: 1}, false},
	} {
		if got := accepts(def, tc.p); got != tc.want {
			t.Errorf("%s: accepted = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A module configured above the absolute limits raises them to what it writes,
// so it still verifies its own hashes, and no further.
func TestVerifyCeilingNeverBelowTheConfiguredCost(t *testing.T) {
	cfg := Config{Memory: 2 * 1024 * 1024, Iterations: 4, Parallelism: 4}
	if got := cfg.verifyCeiling().Memory; got != cfg.Memory {
		t.Errorf("memory ceiling = %d, want the configured %d", got, cfg.Memory)
	}
	if got, want := cfg.verifyWorkCeiling(), uint64(cfg.Memory)*uint64(cfg.Iterations); got != want {
		t.Errorf("work ceiling = %d, want the configured product %d", got, want)
	}
	if accepts(cfg, phc.Params{Memory: cfg.Memory + 1, Iterations: 1, Parallelism: 1}) {
		t.Error("a hash above the configured memory was accepted")
	}
}

// End to end through Verify: a hash one pass over the cap is refused before a
// key is derived, so the call is instant even though the memory is 1 GiB.
func TestVerifyRefusesTheProductBeforeDerivingAKey(t *testing.T) {
	m := fastMod(t, Config{})
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	for _, passes := range []int{5, 20} {
		hash := fmt.Sprintf("$argon2id$v=19$m=1048576,t=%d,p=1$%s$%s", passes, salt, key)
		if ok, err := m.Verify("Correct-Horse-9!", hash); ok || !errors.Is(err, ErrInvalidHash) {
			t.Errorf("1 GiB x %d: Verify = %v, %v; want ErrInvalidHash", passes, ok, err)
		}
	}
}
