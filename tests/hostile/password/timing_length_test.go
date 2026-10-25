package password_test

import (
	"strings"
	"testing"
	"time"
)

// STATISTICAL PROPERTY, not a deterministic one, marked as such.
//
// Verify takes the same time whatever the length of the stored password and
// whatever the length of the attempt, within the noise of a shared runner, so
// the time of a failed login does not tell an observer how long the real
// password is. Argon2id dominates the cost and hashes a fixed-size state, so
// the length of its input moves the time by a few percent at most; the
// tolerance below is a factor of two either way because a test cannot resolve
// less. A Verify that did work proportional to a length, or compared in
// variable time, would fall outside it. Each pair gets three attempts so that
// one noisy run does not fail the suite.
func TestHostile_Timing_lengthOfThePasswordsDoesNotMoveTheTime(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical timing check")
	}
	m := newModule(t, relaxed(1024))
	short, long := "Sh0rt-pass-1!", strings.Repeat("Long-pass-9!", 80) // 13 and 960 runes
	hashShort, err := m.Hash(short)
	if err != nil {
		t.Fatal(err)
	}
	hashLong, err := m.Hash(long)
	if err != nil {
		t.Fatal(err)
	}

	measure := func(attempt, hash string) time.Duration {
		const samples = 15
		d := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			d = append(d, timeVerify(t, m.Verify, attempt, hash))
		}
		return median(d)
	}
	wrongShort, wrongLong := "Wr0ng-pass-1!", strings.Repeat("Wrong-pass-9!", 70)

	for name, pair := range map[string][2][2]string{
		"short attempt, short stored against long stored":  {{wrongShort, hashShort}, {wrongShort, hashLong}},
		"long attempt, short stored against long stored":   {{wrongLong, hashShort}, {wrongLong, hashLong}},
		"short attempt against long attempt, short stored": {{wrongShort, hashShort}, {wrongLong, hashShort}},
	} {
		var ratio float64
		for try := 0; try < 3; try++ {
			a, b := measure(pair[0][0], pair[0][1]), measure(pair[1][0], pair[1][1])
			ratio = float64(a) / float64(b)
			t.Logf("%s (try %d): %v against %v, ratio %.2f", name, try+1, a, b, ratio)
			if ratio >= 0.5 && ratio <= 2.0 {
				break
			}
		}
		if ratio < 0.5 || ratio > 2.0 {
			t.Errorf("%s: timing ratio %.2f is outside [0.5, 2.0] on three tries", name, ratio)
		}
	}
}
