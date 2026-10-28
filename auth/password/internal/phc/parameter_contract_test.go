package phc_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

func TestParseKeepsDocumentedMemoryAndIterationBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		memory, iterations uint32
		wantOK             bool
	}{
		{8191, 1, false},
		{8192, 1, true},
		{4194304, 1, true},
		{4194305, 1, false},
		{8192, 0, false},
		{8192, 20, true},
		{8192, 21, false},
	} {
		t.Run(fmt.Sprintf("memory=%d/iterations=%d", tc.memory, tc.iterations), func(t *testing.T) {
			input := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", tc.memory, tc.iterations,
				"AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			got, salt, key, err := phc.Parse(input)
			if tc.wantOK {
				if err != nil || got.Memory != tc.memory || got.Iterations != tc.iterations || got.Parallelism != 1 || len(salt) != 16 || len(key) != 32 {
					t.Fatalf("canonical parameters changed: %+v, salt=%d, key=%d, err=%v", got, len(salt), len(key), err)
				}
			} else if !errors.Is(err, phc.ErrInvalid) {
				t.Fatalf("out-of-range parameters accepted: %+v, err=%v", got, err)
			}
		})
	}
}
