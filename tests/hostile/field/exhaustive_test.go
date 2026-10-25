package field_test

import (
	"encoding/base64"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
)

// Class: exhaustive mutation and statistics of the stored value.

// Every one of the 255 other values of every byte of the nonce, the first
// ciphertext block and the tag is refused. The single-bit sweep elsewhere
// covers 8 values per byte; this covers all 256, so a byte that is checked only
// partially (a mask, a compare of the high bits) cannot hide.
func TestHostile_Exhaustive_everyValueOfEveryByteOfTheHeaderAndTag(t *testing.T) {
	f := newDeployment(t).column("users.email")
	ct, err := f.Encrypt("alice@example.com") // 17 bytes: two blocks, the second partial
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	// nonce (12) + first block (16), then the last 16 bytes (the tag).
	positions := append(rangeInts(0, 28), rangeInts(len(raw)-16, len(raw))...)
	for _, i := range positions {
		for v := 0; v < 256; v++ {
			if byte(v) == raw[i] {
				continue
			}
			mut := append([]byte(nil), raw...)
			mut[i] = byte(v)
			if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(mut)); got != "" || err != field.ErrDecrypt {
				t.Fatalf("byte %d set to %#02x was accepted: %q, %v", i, v, got, err)
			}
		}
	}
}

func rangeInts(from, to int) []int {
	var out []int
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

// Swapping two bytes, two blocks or two whole values' tags fails, and so does
// splicing the nonce of one value onto the body of another.
func TestHostile_Exhaustive_splicesOfTwoValidValuesAreRefused(t *testing.T) {
	f := newDeployment(t).column("users.email")
	a, _ := f.Encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b, _ := f.Encrypt("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	ra, _ := base64.RawStdEncoding.DecodeString(a)
	rb, _ := base64.RawStdEncoding.DecodeString(b)
	splice := func(parts ...[]byte) string {
		var all []byte
		for _, p := range parts {
			all = append(all, p...)
		}
		return base64.RawStdEncoding.EncodeToString(all)
	}
	n := len(ra)
	for name, v := range map[string]string{
		"nonce of a, body of b":  splice(ra[:12], rb[12:]),
		"nonce of b, body of a":  splice(rb[:12], ra[12:]),
		"tag of b on a":          splice(ra[:n-16], rb[n-16:]),
		"first block of b in a":  splice(ra[:12], rb[12:28], ra[28:]),
		"second block of b in a": splice(ra[:28], rb[28:44], ra[44:]),
		"a then b":               splice(ra, rb),
		"b body then a nonce":    splice(rb[12:], ra[:12]),
	} {
		if got, err := f.Decrypt(v); got != "" || err != field.ErrDecrypt {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// The nonce is uniform, not merely unique. Over 10000 values every byte
// position takes nearly all 256 values, every bit is set about half the time,
// and no two values share a nonce even across two modules built over the same
// secret and context. A counter, a truncated nonce or a nonce taken from the
// plaintext fails at least one of these.
func TestHostile_Nonce_isUniformAcrossPositionsBitsAndModules(t *testing.T) {
	d := newDeployment(t)
	modules := []*field.Field{d.column("users.email"), d.column("users.email")}
	const n = 10000
	var (
		seen    = map[string]bool{}
		perByte [12][256]int
		ones    [96]int
	)
	for i := range n {
		ct, err := modules[i%2].Encrypt("same plaintext every time")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawStdEncoding.DecodeString(ct)
		nonce := raw[:12]
		if seen[string(nonce)] {
			t.Fatalf("nonce repeated after %d values", i)
		}
		seen[string(nonce)] = true
		for p, b := range nonce {
			perByte[p][b]++
			for bit := range 8 {
				if b&(1<<bit) != 0 {
					ones[p*8+bit]++
				}
			}
		}
	}
	for p := range perByte {
		distinct := 0
		for _, c := range perByte[p] {
			if c > 0 {
				distinct++
			}
		}
		if distinct < 250 {
			t.Errorf("nonce byte %d took only %d distinct values in %d draws", p, distinct, n)
		}
	}
	for i, c := range ones {
		if frac := float64(c) / n; frac < 0.46 || frac > 0.54 {
			t.Errorf("nonce bit %d is set in %.1f%% of values", i, frac*100)
		}
	}
}

// Encrypt, Decrypt and BlindIndex all at once on one module, from many
// goroutines (run with -race): every result is correct and no nonce repeats.
func TestHostile_Nonce_concurrentMixedUseOfOneModule(t *testing.T) {
	f := newDeployment(t).column("users.email")
	base, _ := f.Encrypt("seed value")
	wantIdx := mustIndex(t, f, "seed value")
	var (
		mu     sync.Mutex
		nonces = map[string]bool{}
		wg     sync.WaitGroup
	)
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1500 {
				switch (g + i) % 3 {
				case 0:
					ct, err := f.Encrypt("value")
					if err != nil {
						t.Error(err)
						return
					}
					raw, _ := base64.RawStdEncoding.DecodeString(ct)
					mu.Lock()
					if nonces[string(raw[:12])] {
						t.Error("a nonce repeated under concurrent use")
					}
					nonces[string(raw[:12])] = true
					mu.Unlock()
				case 1:
					if got, err := f.Decrypt(base); err != nil || got != "seed value" {
						t.Errorf("concurrent Decrypt = %q, %v", got, err)
						return
					}
				default:
					if got, err := f.BlindIndex("seed value"); err != nil || got != wantIdx {
						t.Errorf("concurrent BlindIndex = %q, %v", got, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
