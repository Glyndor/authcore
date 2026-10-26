// Package phc attacks hash verification: malformed PHC strings, mutated
// hashes, shared salts and agreement with a reference Argon2.
package phc

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// The stored hash is data the module parses before it does any work. A hash
// that is not exactly what Hash writes is refused with ErrInvalidHash and a
// false result, never accepted and never turned into work for the CPU.
func TestHostile_PHC_malformedHashesAreRefused(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	good, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := m.Verify(hostiletest.Strong, good)
	if err != nil || !ok {
		t.Fatalf("control: Verify = %v, %v", ok, err)
	}

	p := hostiletest.Parts(t, good)
	salt, key := p[4], p[5]
	withParams := func(params string) string { return hostiletest.Join("", "argon2id", "v=19", params, salt, key) }

	cases := map[string]string{
		// Algorithm.
		"empty":             "",
		"dollar only":       "$",
		"argon2i":           hostiletest.Join("", "argon2i", p[2], p[3], salt, key),
		"argon2d":           hostiletest.Join("", "argon2d", p[2], p[3], salt, key),
		"argon2ID casing":   hostiletest.Join("", "argon2ID", p[2], p[3], salt, key),
		"argon2id padded":   hostiletest.Join("", "argon2id ", p[2], p[3], salt, key),
		"bcrypt":            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"md5 crypt":         "$1$salt$qJH7.N4xYta3aEG/dfqo/0",
		"plaintext":         hostiletest.Strong,
		"prefix junk":       "x" + good,
		"leading space":     " " + good,
		"trailing space":    good + " ",
		"trailing newline":  good + "\n",
		"trailing NUL":      good + "\x00",
		"NUL in the middle": good[:30] + "\x00" + good[30:],
		// Version.
		"version 16":          hostiletest.Join("", "argon2id", "v=16", p[3], salt, key),
		"version 0":           hostiletest.Join("", "argon2id", "v=0", p[3], salt, key),
		"version 19 padded":   hostiletest.Join("", "argon2id", "v=019", p[3], salt, key),
		"version plus":        hostiletest.Join("", "argon2id", "v=+19", p[3], salt, key),
		"version hex":         hostiletest.Join("", "argon2id", "v=0x13", p[3], salt, key),
		"version negative":    hostiletest.Join("", "argon2id", "v=-19", p[3], salt, key),
		"version overflow":    hostiletest.Join("", "argon2id", "v=4294967315", p[3], salt, key),
		"version missing":     hostiletest.Join("", "argon2id", p[3], salt, key),
		"version empty":       hostiletest.Join("", "argon2id", "v=", p[3], salt, key),
		"version label upper": hostiletest.Join("", "argon2id", "V=19", p[3], salt, key),
		// Parameters.
		"m zero":             withParams("m=0,t=1,p=1"),
		"m one":              withParams("m=1,t=1,p=1"),
		"m just under min":   withParams("m=8191,t=1,p=1"),
		"m just over max":    withParams("m=4194305,t=1,p=1"),
		"m uint32 max":       withParams("m=4294967295,t=1,p=1"),
		"m uint32 overflow":  withParams("m=4294967296,t=1,p=1"),
		"m negative":         withParams("m=-8192,t=1,p=1"),
		"m fraction":         withParams("m=8192.5,t=1,p=1"),
		"m leading zeros":    withParams("m=008192,t=1,p=1"),
		"m plus sign":        withParams("m=+8192,t=1,p=1"),
		"m hex":              withParams("m=0x2000,t=1,p=1"),
		"m fullwidth digits": withParams("m=\uff18\uff11\uff19\uff12,t=1,p=1"),
		"m empty":            withParams("m=,t=1,p=1"),
		"t zero":             withParams("m=8192,t=0,p=1"),
		"t just over max":    withParams("m=8192,t=21,p=1"),
		"t uint32 max":       withParams("m=8192,t=4294967295,p=1"),
		"t negative":         withParams("m=8192,t=-1,p=1"),
		"p zero":             withParams("m=8192,t=1,p=0"),
		"p 256":              withParams("m=8192,t=1,p=256"),
		"p negative":         withParams("m=8192,t=1,p=-1"),
		"p uint32 max":       withParams("m=8192,t=1,p=4294967295"),
		"reordered":          withParams("t=1,m=8192,p=1"),
		"extra parameter":    withParams("m=8192,t=1,p=1,keyid=a"),
		"missing parameter":  withParams("m=8192,t=1"),
		"duplicate m":        withParams("m=8192,m=8192,p=1"),
		"upper-case labels":  withParams("M=8192,T=1,P=1"),
		"spaces in params":   withParams("m=8192, t=1, p=1"),
		"semicolons":         withParams("m=8192;t=1;p=1"),
		"empty params":       withParams(""),
		// Salt and key.
		"salt empty":        hostiletest.Join("", "argon2id", p[2], p[3], "", key),
		"salt 15 bytes":     hostiletest.Join("", "argon2id", p[2], p[3], hostiletest.Enc(15), key),
		"salt 17 bytes":     hostiletest.Join("", "argon2id", p[2], p[3], hostiletest.Enc(17), key),
		"salt one MiB":      hostiletest.Join("", "argon2id", p[2], p[3], strings.Repeat("A", 1<<20), key),
		"key empty":         hostiletest.Join("", "argon2id", p[2], p[3], salt, ""),
		"key 31 bytes":      hostiletest.Join("", "argon2id", p[2], p[3], salt, hostiletest.Enc(31)),
		"key 33 bytes":      hostiletest.Join("", "argon2id", p[2], p[3], salt, hostiletest.Enc(33)),
		"key four MiB":      hostiletest.Join("", "argon2id", p[2], p[3], salt, strings.Repeat("A", 4<<20)),
		"padded salt":       hostiletest.Join("", "argon2id", p[2], p[3], salt+"==", key),
		"padded key":        hostiletest.Join("", "argon2id", p[2], p[3], salt, key+"="),
		"url alphabet salt": hostiletest.Join("", "argon2id", p[2], p[3], strings.NewReplacer("+", "-", "/", "_").Replace(salt)+"-", key),
		"space in salt":     hostiletest.Join("", "argon2id", p[2], p[3], salt[:5]+" "+salt[5:], key),
		"newline in key":    hostiletest.Join("", "argon2id", p[2], p[3], salt, key[:5]+"\n"+key[5:]),
		"unicode in salt":   hostiletest.Join("", "argon2id", p[2], p[3], salt[:5]+"\u00e9"+salt[6:], key),
		// Shape.
		"seven segments":  good + "$extra",
		"trailing dollar": good + "$",
		"five segments":   hostiletest.Join("", "argon2id", p[2], p[3], salt),
		"doubled":         good + good,
		"dollar in key":   hostiletest.Join("", "argon2id", p[2], p[3], salt, key[:10]+"$"+key[11:]),
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			ok, err := m.Verify(hostiletest.Strong, hash)
			if ok {
				t.Fatalf("Verify accepted a hostile hash: %.80q", hash)
			}
			if !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("Verify error = %v, want ErrInvalidHash", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("refusing took %v: the hash cost work before it was refused", d)
			}
		})
	}
}

// A wrong password against a valid hash is a mismatch, not a malformed hash.
// The two stay distinguishable so a caller does not treat a typo as corruption.
func TestHostile_PHC_wrongPasswordIsAMismatchNotAnError(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	good, _ := m.Hash(hostiletest.Strong)
	for _, wrong := range []string{"", hostiletest.Strong + "x", hostiletest.Strong[:len(hostiletest.Strong)-1], strings.ToUpper(hostiletest.Strong), hostiletest.Strong + "\x00", "x"} {
		ok, err := m.Verify(wrong, good)
		if ok || err != nil {
			t.Errorf("Verify(%q) = %v, %v; want false, nil", wrong, ok, err)
		}
	}
}

// Flipping any one character of the stored hash either makes it malformed or
// makes it a hash of something else; the original password never verifies
// against the altered hash.
func TestHostile_PHC_everySingleCharacterChangeInTheKeyIsRefused(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	good, _ := m.Hash(hostiletest.Strong)
	keyStart := strings.LastIndexByte(good, '$') + 1
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := keyStart; i < len(good); i++ {
		pos := strings.IndexByte(alphabet, good[i])
		alt := alphabet[(pos+1)%64]
		altered := good[:i] + string(alt) + good[i+1:]
		if ok, _ := m.Verify(hostiletest.Strong, altered); ok {
			t.Fatalf("a hash with key character %d changed verified", i-keyStart)
		}
	}
}

// Two hashes of one password differ (a fresh salt each time) and both verify,
// so a hash table lifted from the database does not reveal who shares a
// password.
func TestHostile_PHC_saltIsFreshPerHash(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		h, err := m.Hash(hostiletest.Strong)
		if err != nil {
			t.Fatal(err)
		}
		salt := hostiletest.Parts(t, h)[4]
		if seen[salt] {
			t.Fatalf("salt repeated after %d hashes", i)
		}
		seen[salt] = true
		if ok, err := m.Verify(hostiletest.Strong, h); err != nil || !ok {
			t.Fatalf("hash %d does not verify: %v, %v", i, ok, err)
		}
	}
}
