package verifier_test

import (
	"encoding/base32"
	"errors"
	"testing"
)

// FuzzVerifyStepWindow checks VerifyStep against the window rule written out
// with plain integers: for any clock reading, skew, step offset and stored
// step, a code is accepted when it is inside the window and newer than the
// stored step, reported as reuse when inside the window but not newer, and
// invalid otherwise.
func FuzzVerifyStepWindow(f *testing.F) {
	f.Add(int64(1_700_000_000), uint8(1), int8(0), uint64(0))
	f.Add(int64(1_700_000_000), uint8(1), int8(-1), uint64(56_666_666))
	f.Add(int64(1_700_000_000), uint8(1), int8(2), uint64(0))
	f.Add(int64(1_700_000_029), uint8(0), int8(0), uint64(56_666_665))
	f.Add(int64(253_402_300_799), uint8(10), int8(-10), uint64(1))
	f.Add(int64(1<<40), uint8(3), int8(4), uint64(1<<62))

	f.Add(int64(31556160*30), uint8(10), int8(-9), uint64(0))
	f.Add(int64(31556160*30+60), uint8(10), int8(-4), uint64(31556158))
	f.Fuzz(func(t *testing.T, sec int64, skewIn uint8, offset int8, lastUsed uint64) {
		skew := int(skewIn % 11)
		if sec < int64(skew+2)*timeStep || sec > 1<<58 {
			return // the first steps of 1970 and absurd years are not the clock's domain
		}
		const secret = "AAAAAAAAAABZ6AAAAAAAAAAAAAAAAAAA"
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			t.Fatal(err)
		}
		if hotpOracle(key, 31556151) != "604344" || hotpOracle(key, 31556158) != "604344" {
			t.Fatal("collision fixture changed")
		}
		m := newTOTP(t, Config{SkewSteps: Int(skew)})
		atUnix(m, sec, 0)
		cur := sec / timeStep
		step := cur + int64(offset)
		if step < 0 {
			return
		}
		code := hotpOracle(key, uint64(step))

		inside := false // does this code equal the code of any step in the window?
		var matched uint64
		for s := cur - int64(skew); s <= cur+int64(skew); s++ {
			if hotpOracle(key, uint64(s)) == code {
				inside, matched = true, uint64(s) // the module keeps the highest match
			}
		}
		got, err := m.VerifyStep(secret, code, lastUsed)
		switch {
		case !inside:
			if !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("clock %d skew %d offset %d: outside the window, err = %v", sec, skew, offset, err)
			}
		case matched <= lastUsed:
			if !errors.Is(err, ErrCodeReused) {
				t.Fatalf("clock %d skew %d step %d lastUsed %d: err = %v, want reuse", sec, skew, matched, lastUsed, err)
			}
		default:
			if err != nil || got != matched {
				t.Fatalf("clock %d skew %d step %d lastUsed %d: = %d, %v; want %d", sec, skew, matched, lastUsed, got, err, matched)
			}
		}
	})
}
