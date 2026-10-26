package tokenid_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/tokenid"
)

const validJTI = "018f0c8e-9b2a-7c3a-8b1e-1234567890ab"

// Changing any single character of a valid identifier to something outside its
// alphabet must be refused, at every position and for every field separator.
func TestIsUUIDv7_refusesAnyOneBadCharacter(t *testing.T) {
	if !tokenid.IsUUIDv7(validJTI) {
		t.Fatal("control identifier refused")
	}
	for i := 0; i < len(validJTI); i++ {
		for _, bad := range []string{"g", "-", " ", "\x00", "é"} {
			got := validJTI[:i] + bad + validJTI[i+1:]
			if validJTI[i] == '-' && bad == "-" {
				continue
			}
			if tokenid.IsUUIDv7(got) {
				t.Errorf("position %d replaced by %q was accepted: %q", i, bad, got)
			}
		}
	}
	// A hex digit where a separator belongs is as wrong as a letter.
	for _, i := range []int{8, 13, 18, 23} {
		got := validJTI[:i] + "0" + validJTI[i+1:]
		if tokenid.IsUUIDv7(got) {
			t.Errorf("hex digit in place of the separator at %d was accepted: %q", i, got)
		}
	}
}

// NewJTI keeps the random bits random: apart from the version and variant
// fields every hex digit takes every value, and the fixed fields never move.
func TestNewJTI_fixedFieldsAreFixedAndTheRestIsRandom(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_123)
	seen := map[int]map[byte]bool{}
	for i := 0; i < 3000; i++ {
		id, err := tokenid.NewJTI(now)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 36 || id[14] != '7' || !strings.ContainsRune("89ab", rune(id[19])) {
			t.Fatalf("version or variant field wrong in %q", id)
		}
		if id[:13] != "018bcfe5-687b" {
			t.Fatalf("timestamp field moved in %q", id)
		}
		for pos := 14; pos < len(id); pos++ {
			if seen[pos] == nil {
				seen[pos] = map[byte]bool{}
			}
			seen[pos][id[pos]] = true
		}
	}
	for pos := 15; pos < 36; pos++ {
		switch pos {
		case 18, 23:
			continue
		case 19:
			if len(seen[pos]) != 4 {
				t.Errorf("variant digit took %d values, want 4: %v", len(seen[pos]), seen[pos])
			}
		default:
			if len(seen[pos]) != 16 {
				t.Errorf("position %d took %d values, want 16", pos, len(seen[pos]))
			}
		}
	}
}
