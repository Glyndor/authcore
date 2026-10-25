package hotp

import "testing"

// RFC 6238 Appendix B publishes eight-digit SHA1 values for the secret
// "12345678901234567890"; the six-digit code is their last six digits.
func TestGenerate_RFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		step := uint64(v.unix) / TimeStep
		if got := Generate(key, step); got != v.want {
			t.Errorf("Generate(t=%d) = %s, want %s", v.unix, got, v.want)
		}
		if !Matches(step, key, v.want) {
			t.Errorf("Matches(t=%d, %s) = false", v.unix, v.want)
		}
		if Matches(step, key, "000000") && v.want != "000000" {
			t.Errorf("Matches(t=%d) accepted a wrong code", v.unix)
		}
	}
}

func TestIsSixDigits(t *testing.T) {
	for in, want := range map[string]bool{
		"123456":  true,
		"000000":  true,
		"":        false,
		"12345":   false,
		"1234567": false,
		"12345a":  false,
		"12 456":  false,
		"１２３４５６":  false, // fullwidth digits
	} {
		if got := IsSixDigits(in); got != want {
			t.Errorf("IsSixDigits(%q) = %v, want %v", in, got, want)
		}
	}
}
