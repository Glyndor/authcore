package credential

import "testing"

// Known answer: the stored hash is HMAC-SHA256 under the refresh secret of
// the purpose, the subject and the token, each prefixed by its length as a
// big-endian uint32, hex encoded. The expected value was computed outside
// Go. A change here silently invalidates every stored credential hash.
func TestComputeHash_knownAnswer(t *testing.T) {
	c, err := New(fakeProvider{keys: fakeKeys{secret: []byte("0123456789abcdef0123456789abcdef")}})
	if err != nil {
		t.Fatal(err)
	}
	got := c.computeHash("reset", "018f0c8e-9b2a-7c3a-8b1e-1234567890ab", "tok")
	const want = "f5cfebd957fb98613899f437118c7beabc616689d52de182d3e8d28b33f03069"
	if got != want {
		t.Fatalf("computeHash = %s, want %s: the stored-hash format changed", got, want)
	}
}
