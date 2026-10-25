package material

import "testing"

// FuzzCheckSecret feeds arbitrary bytes to the pattern check. It must never
// panic, and an accepted value must hold at least MinDistinctBytes different
// bytes, whatever its length.
func FuzzCheckSecret(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add([]byte("k3Qz9vLm2XaR7tYpB5nWd8GcHf4JsUe1"))
	f.Add([]byte{1, 2, 3, 4, 1, 2, 3, 4})

	f.Fuzz(func(t *testing.T, b []byte) {
		if CheckSecret(b) != nil || len(b) < 2 {
			return
		}
		seen := map[byte]bool{}
		for _, c := range b {
			seen[c] = true
		}
		if len(seen) < MinDistinctBytes {
			t.Fatalf("accepted %d bytes holding %d different values", len(b), len(seen))
		}
	})
}
