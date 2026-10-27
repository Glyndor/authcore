package confusion

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

func TestMisuse_Password_SwappedArgumentsNeverEchoPlaintext(t *testing.T) {
	e := hostiletest.NewEnv(t)
	pw, err := password.New(e.AC, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, plain, sensitive string }{
		{"no-dollars-control", "Canary-Horse-9-Battery", "Canary-Horse-9-Battery"},
		{"first-segment", "Canary-Horse-9$second$third$fourth$fifth$sixth", "Canary-Horse-9"},
		{"algorithm-segment", "$Canary-Horse-9$third$fourth$fifth$sixth", "Canary-Horse-9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := pw.Hash(tc.plain)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := pw.Verify(tc.plain, hash); err != nil || !ok {
				t.Fatalf("control: normal argument order: ok=%v err=%v", ok, err)
			}
			ok, err := pw.Verify(hash, tc.plain)
			if ok || !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("swapped arguments: ok=%v err=%v", ok, err)
			}
			if strings.Contains(err.Error(), tc.plain) || strings.Contains(err.Error(), tc.sensitive) {
				t.Error("invalid-hash error echoed plaintext")
			}
		})
	}
}
