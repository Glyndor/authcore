package hotp

import (
	"math/rand/v2"
	"sort"
	"testing"
	"time"
)

// Statistical guard at the comparison primitive: a fixed step avoids clock
// rollover and excludes secret decoding and the replay recorder from timing.
// The tolerance detects substantial prefix-dependent work, not nanosecond leaks
// on a shared runner. It is not a proof of constant-time machine code.
func TestHostile_TOTP_WrongCodeTimingDoesNotRevealMatchingPrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical timing check")
	}
	key := []byte("12345678901234567890")
	const step = uint64(1234567890 / TimeStep)
	right := Generate(key, step)
	if !Matches(step, key, right) {
		t.Fatal("control: generated code did not match")
	}
	var wrong [Digits]string
	for prefix := range wrong {
		b := []byte(right)
		b[prefix] = '0' + (b[prefix]-'0'+1)%10
		wrong[prefix] = string(b)
		if !IsSixDigits(wrong[prefix]) || Matches(step, key, wrong[prefix]) {
			t.Fatal("control: invalid wrong-code fixture")
		}
	}
	const rounds, batch = 31, 4096
	var samples [Digits][]time.Duration
	rng := rand.New(rand.NewPCG(71, 93))
	measure := func(code string) time.Duration {
		start := time.Now()
		accepted := false
		for range batch {
			accepted = Matches(step, key, code) || accepted
		}
		elapsed := time.Since(start)
		if accepted {
			t.Fatal("a wrong code matched during measurement")
		}
		return elapsed
	}
	// Warm both allocation and HMAC paths before collecting samples.
	for _, code := range wrong {
		measure(code)
	}
	for range rounds {
		for _, prefix := range rng.Perm(Digits) {
			samples[prefix] = append(samples[prefix], measure(wrong[prefix]))
		}
	}
	var fastest, slowest time.Duration
	for prefix := range samples {
		sort.Slice(samples[prefix], func(i, j int) bool { return samples[prefix][i] < samples[prefix][j] })
		median := samples[prefix][rounds/2]
		t.Logf("matching prefix %d: median batch %v", prefix, median)
		if fastest == 0 || median < fastest {
			fastest = median
		}
		if median > slowest {
			slowest = median
		}
	}
	ratio := float64(slowest) / float64(fastest)
	if ratio > 1.30 {
		t.Fatalf("wrong-code cost depends on matching prefix: max/min median ratio %.3f > 1.30", ratio)
	}
}
