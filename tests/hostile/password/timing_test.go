package password_test

import (
	"sort"
	"testing"
	"time"
)

// STATISTICAL PROPERTY, not a deterministic one.
//
// An observer who sees only how long a login takes must not be able to tell a
// right password from a wrong one. Argon2id dominates the time, so the medians
// of the two should be close. The tolerance is wide on purpose (a factor of two
// either way) because a test cannot resolve a constant-time comparison at
// nanosecond scale on a shared runner. What it does catch is the gross failure:
// a Verify that returns early on a mismatch or does extra work on a match.
func TestHostile_Timing_rightAndWrongPasswordsCostTheSame(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical timing check")
	}
	m := newModule(t, lowCost())
	hash, err := m.Hash(strong)
	if err != nil {
		t.Fatal(err)
	}
	const samples = 15
	right := make([]time.Duration, 0, samples)
	wrongEarly := make([]time.Duration, 0, samples)
	wrongLate := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		right = append(right, timeVerify(t, m.Verify, strong, hash))
		wrongEarly = append(wrongEarly, timeVerify(t, m.Verify, "X"+strong[1:], hash))
		wrongLate = append(wrongLate, timeVerify(t, m.Verify, strong[:len(strong)-1]+"X", hash))
	}
	r := median(right)
	for name, other := range map[string][]time.Duration{"wrong first character": wrongEarly, "wrong last character": wrongLate} {
		ratio := float64(median(other)) / float64(r)
		t.Logf("%s: median %v against %v for the right password (ratio %.2f)", name, median(other), r, ratio)
		if ratio < 0.5 || ratio > 2.0 {
			t.Errorf("%s: timing ratio %.2f is outside [0.5, 2.0]", name, ratio)
		}
	}
}

func timeVerify(t *testing.T, verify func(string, string) (bool, error), pw, hash string) time.Duration {
	t.Helper()
	start := time.Now()
	if _, err := verify(pw, hash); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

func median(d []time.Duration) time.Duration {
	c := append([]time.Duration(nil), d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}
