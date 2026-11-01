package claimread

import (
	"encoding/json"
	"math/big"
	"strconv"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// FuzzDateInRange feeds DateInRange the same number as a float64 claim and as
// a json.Number claim, and judges both against an exact comparison done with
// math/big: the value must be at least 0 and below 253402300800 (the first
// second of year 10000). The reference shares no code with the function, so a
// verifier that refuses everything, or accepts a NaN or an infinity, cannot
// pass by agreeing with itself.
func FuzzDateInRange(f *testing.F) {
	for _, seed := range []string{
		"0", "-0", "-0.5", "-1", "0.5", "1.5", "253402300799", "253402300799.9",
		"253402300800", "1e100", "-1e100", "1e400", "9223372036854775807",
		"9223372036854775808", "NaN", "Inf", "-Inf", "1e-400", "0x1p3", "",
	} {
		f.Add(seed)
	}

	lo := new(big.Float).SetInt64(minNumericDate)
	hi := new(big.Float).SetInt64(maxNumericDate + 1)

	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := strconv.ParseFloat(text, 64)
		want := false
		if err == nil && parsed == parsed { // a parse error or NaN is never a date
			v := new(big.Float).SetFloat64(parsed) // exact; panics on NaN, hence the check above
			want = v.Cmp(lo) >= 0 && v.Cmp(hi) < 0
		}

		if err == nil {
			if got := DateInRange(gjwt.MapClaims{"nbf": parsed}, "nbf"); got != want {
				t.Fatalf("DateInRange(float64 %v) = %v, want %v", parsed, got, want)
			}
		}
		if got := DateInRange(gjwt.MapClaims{"nbf": json.Number(text)}, "nbf"); got != want {
			t.Fatalf("DateInRange(json.Number %q) = %v, want %v", text, got, want)
		}
	})
}
