package material_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/material"
)

// withDistinct returns 32 bytes that hold exactly k different values, in an
// order that is neither a counting sequence nor a repeating block.
func withDistinct(k int) []byte {
	b := make([]byte, 32)
	state := uint32(7)
	for i := range b {
		state = state*1103515245 + 12345
		sym := int(state>>16) % k
		if i < k {
			sym = (i * 5) % k // k is coprime with 5 for the sizes used here
		}
		b[i] = byte(sym*17 + 3)
	}
	return b
}

func refusalFor(t *testing.T, b []byte) string {
	t.Helper()
	if err := material.CheckSecret(b); err != nil {
		return err.Error()
	}
	return ""
}

func TestCheckSecret_DistinctValueThresholdIsTwelve(t *testing.T) {
	if material.MinDistinctBytes != 12 {
		t.Fatalf("MinDistinctBytes = %d, want 12", material.MinDistinctBytes)
	}
	if msg := refusalFor(t, withDistinct(12)); msg != "" {
		t.Errorf("12 different values were refused: %s", msg)
	}
	if msg := refusalFor(t, withDistinct(11)); !strings.Contains(msg, "too few different byte values") {
		t.Errorf("11 different values: %q, want the too-few-values refusal", msg)
	}
}

func TestCheckSecret_ShortInputs(t *testing.T) {
	for _, b := range [][]byte{nil, {0x42}} {
		if msg := refusalFor(t, b); msg != "" {
			t.Errorf("%d byte(s) were refused: %s", len(b), msg)
		}
	}
	// Two bytes are always a "constant stride", so they are refused.
	if refusalFor(t, []byte{0x01, 0x09}) == "" {
		t.Error("a two-byte value was accepted as random-looking")
	}
}

// Only the very first step is allowed to differ from the rest for the value to
// stop being a counting sequence: two runs with a jump after the second byte.
func TestCheckSecret_CountingSequenceWithAJumpAfterTwoBytesIsNotCounting(t *testing.T) {
	b := make([]byte, 32)
	b[0], b[1] = 1, 2
	for i := 2; i < len(b); i++ {
		b[i] = byte(10 + i)
	}
	if msg := refusalFor(t, b); msg != "" {
		t.Fatalf("a sequence with one jump was refused: %s", msg)
	}
}

// A repeating block is refused, but a block repeated except for its very first
// byte is not a repeating block.
func TestCheckSecret_RepeatedBlockMustMatchFromTheFirstByte(t *testing.T) {
	const period = 13
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte((i%period)*11 + 5)
	}
	if msg := refusalFor(t, b); !strings.Contains(msg, "short block repeated") {
		t.Fatalf("a repeated 13-byte block: %q, want the repeated-block refusal", msg)
	}

	b[0] = 250
	if msg := refusalFor(t, b); msg != "" {
		t.Fatalf("a block whose first byte differs from its copies was refused: %s", msg)
	}
}
