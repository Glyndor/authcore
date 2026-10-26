package material

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func run(n int, f func(i int) byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = f(i)
	}
	return b
}

func TestCheckSecret_refusesPatternedValues(t *testing.T) {
	cases := map[string][]byte{
		"zeros":        make([]byte, 32),
		"one value":    bytes.Repeat([]byte{0xab}, 32),
		"ascending":    run(32, func(i int) byte { return byte(i) }),
		"from one":     run(32, func(i int) byte { return byte(i + 1) }),
		"wrapping":     run(32, func(i int) byte { return byte(200 + i) }),
		"descending":   run(32, func(i int) byte { return byte(255 - i) }),
		"step of two":  run(32, func(i int) byte { return byte(2 * i) }),
		"block of 2":   bytes.Repeat([]byte{1, 2}, 16),
		"block of 3":   append(bytes.Repeat([]byte{9, 8, 7}, 10), 9, 8),
		"two halves":   append(run(16, func(i int) byte { return byte(i*41 + 3) }), run(16, func(i int) byte { return byte(i*41 + 3) })...),
		"block of 4":   bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 8),
		"eleven kinds": run(32, func(i int) byte { return byte(i * 7 % 11) }),
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			err := CheckSecret(secret)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "refresh secret") || !strings.Contains(err.Error(), "random") {
				t.Errorf("the refusal does not name the item and the rule: %v", err)
			}
		})
	}
}

// The threshold sits in the middle of nothing a generator produces: twelve
// different values is the smallest set accepted.
func TestCheckSecret_distinctValueThreshold(t *testing.T) {
	// Every value shows up once in the first n bytes; the rest follow a
	// sequence that is not periodic.
	kinds := func(n int) []byte {
		return run(32, func(i int) byte {
			if i < n {
				return byte(i*37 + 5)
			}
			return byte((i*i/3+i)%n*37 + 5)
		})
	}
	if err := CheckSecret(kinds(MinDistinctBytes - 1)); err == nil {
		t.Errorf("%d distinct values accepted", MinDistinctBytes-1)
	}
	if err := CheckSecret(kinds(MinDistinctBytes)); err != nil {
		t.Errorf("%d distinct values refused: %v", MinDistinctBytes, err)
	}
}

func TestCheckSecret_neverRefusesRandomBytes(t *testing.T) {
	for i := 0; i < 20000; i++ {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if err := CheckSecret(b); err != nil {
			t.Fatalf("random value refused: %v", err)
		}
	}
}

func TestCheckSecret_shortInputIsNotJudged(t *testing.T) {
	for _, b := range [][]byte{nil, {1}} {
		if err := CheckSecret(b); err != nil {
			t.Errorf("%d byte input: %v", len(b), err)
		}
	}
}

func TestCheckSeed(t *testing.T) {
	if err := CheckSeed(ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil ||
		!strings.Contains(err.Error(), "signing key seed") {
		t.Errorf("zero seed: %v", err)
	}
	priv, _ := genPair(t)
	if err := CheckSeed(priv); err != nil {
		t.Errorf("random seed refused: %v", err)
	}
}

func TestValidate_refusesWeakMaterialAfterShapeChecks(t *testing.T) {
	priv, pub := genPair(t)
	if err := Validate(priv, pub, make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "refresh secret") {
		t.Errorf("zero secret: %v", err)
	}
	weak := ed25519.NewKeyFromSeed(make([]byte, 32))
	secret := run(32, func(i int) byte { return byte(i*37 + 11) })
	if err := Validate(weak, weak.Public().(ed25519.PublicKey), secret); err == nil || !strings.Contains(err.Error(), "signing key seed") {
		t.Errorf("zero seed: %v", err)
	}
}
