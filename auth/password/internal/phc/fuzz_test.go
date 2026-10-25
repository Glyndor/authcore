package phc_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// FuzzParsePHC drives the PHC parser with arbitrary stored hashes. It must
// never panic, and anything it accepts must be the exact string Hash would
// write for the parameters, salt and key it returned. A non-canonical string
// that parses verifies the same password its canonical form does; that is how
// "junk" + hash (#437) and m=4294975488 read as m=8192 (#451) got through,
// and a no-panic oracle saw neither.
func FuzzParsePHC(f *testing.F) {
	seeds := []string{
		"", "$", "$$$$$$",
		"$argon2id$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2i$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=99$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=x,t=y,p=z$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!!$AAAA",
	}
	// The seeds above all fail on salt or key length, so without one valid
	// hash the fuzzer rarely reaches the end of the parser and the oracle
	// below never runs. This one parses.
	seeds = append(seeds, fmt.Sprintf("$argon2id$v=%d$m=%d,t=3,p=2$%s$%s", argon2.Version, phc.MinMemory,
		base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("s", phc.SaltLen))),
		base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("k", phc.KeyLen)))))
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		cfg, salt, key, err := phc.Parse(in)
		if err != nil {
			return
		}
		canonical := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version, cfg.Memory, cfg.Iterations, cfg.Parallelism,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(key))
		if in != canonical {
			t.Fatalf("phc.Parse accepted a non-canonical hash:\n got  %q\n want %q", in, canonical)
		}
	})
}
