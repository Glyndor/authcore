package recovery_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp/internal/recovery"
)

func TestFindRefusesMoreThanSixteenSignificantCharactersEvenWithAMatchingHash(t *testing.T) {
	t.Parallel()
	key := []byte("recovery-limit-test-pepper")
	for _, size := range []int{16, 17, 18, 21} {
		code := strings.Repeat("a", size)
		stored := []string{recovery.Hash(key, code)}
		idx, ok := recovery.Find(key, " -- "+code+" - ", stored)
		if size == 16 {
			if !ok || idx != 0 {
				t.Fatalf("sixteen-character code did not match: index=%d, ok=%v", idx, ok)
			}
		} else if ok {
			t.Fatalf("%d-character code matched despite the content limit", size)
		}
	}
}
