package tokenid

import "testing"

// FuzzIsUUIDv7 checks IsUUIDv7 against uuidV7Shape, which is RFC 9562
// section 5.7 written apart from IsUUIDv7: eight, four, "7" plus three, one of
// [89ab] plus three, and twelve hex digits.
func FuzzIsUUIDv7(f *testing.F) {
	seeds := []string{
		"", "not-a-uuid",
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ab",
		"018f0c8e-9b2a-7c3a-cb1e-1234567890ab", // variant c
		"018F0C8E-9B2A-7C3A-8B1E-1234567890AB",
		"018f0c8e-9b2a-4c3a-8b1e-1234567890ab", // version 4
		"018f0c8e9-b2a-7c3a-8b1e-1234567890ab", // a dash moved
		"018f0c8e09b2a07c3a08b1e01234567890ab", // hex digits where the dashes go: only the dash check refuses it
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ag", // a non-hex byte
		"018f0c8e-9b2a-7c3a-8b1e-1234567890a",  // one short
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		if got, want := IsUUIDv7(in), uuidV7Shape.MatchString(in); got != want {
			t.Fatalf("IsUUIDv7(%q) = %v, the shape says %v", in, got, want)
		}
	})
}
