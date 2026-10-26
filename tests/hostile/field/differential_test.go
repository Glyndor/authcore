package field_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
)

// Class: differential properties. The module and the oracle in oracle_test.go
// are run on the same arbitrary inputs, in both directions.

// randomBytes returns n bytes from the CSPRNG.
func randomBytes(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func randomInt(t testing.TB, n int) int {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatal(err)
	}
	return int(v.Int64())
}

// sizes straddle every boundary that matters to GCM: the 16 byte block, the
// counter's 32 bit wrap region is out of reach, and the 12 byte nonce.
var boundarySizes = []int{0, 1, 11, 12, 13, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1023, 4096, 65535, 65536, 65537}

func TestHostile_Differential_moduleAndOracleAgreeInBothDirections(t *testing.T) {
	d := newDeployment(t)
	for _, ctxLen := range []int{1, 2, 15, 16, 17, 255, 4096} {
		context := randomBytes(t, ctxLen)
		f := d.column(context)
		o := newOracle(t, d.pepper, context)
		for _, size := range boundarySizes {
			p := randomBytes(t, size)

			ct, err := f.Encrypt(p)
			if err != nil {
				t.Fatalf("ctx %d, plaintext %d: Encrypt: %v", ctxLen, size, err)
			}
			if got, ok := o.open(ct); !ok || got != p {
				t.Fatalf("ctx %d, plaintext %d: the oracle cannot open the module's ciphertext", ctxLen, size)
			}
			if got, err := f.Decrypt(o.seal(p)); err != nil || got != p {
				t.Fatalf("ctx %d, plaintext %d: the module cannot open the oracle's ciphertext: %v", ctxLen, size, err)
			}
			if got, want := mustIndex(t, f, p), o.blindIndex(p); got != want {
				t.Fatalf("ctx %d, value %d: BlindIndex = %s, oracle %s", ctxLen, size, got, want)
			}
		}
	}
}

func mustIndex(t testing.TB, f *field.Field, v string) string {
	t.Helper()
	idx, err := f.BlindIndex(v)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// Random shapes rather than a fixed table: sizes and contexts drawn per round.
func TestHostile_Differential_randomShapes(t *testing.T) {
	d := newDeployment(t)
	for range 300 {
		context := randomBytes(t, 1+randomInt(t, 300))
		f := d.column(context)
		o := newOracle(t, d.pepper, context)
		p := randomBytes(t, randomInt(t, 2000))

		ct, _ := f.Encrypt(p)
		if got, ok := o.open(ct); !ok || got != p {
			t.Fatal("the oracle cannot open the module's ciphertext")
		}
		if got, err := f.Decrypt(o.seal(p)); err != nil || got != p {
			t.Fatalf("the module cannot open the oracle's ciphertext: %v", err)
		}
		if mustIndex(t, f, p) != o.blindIndex(p) {
			t.Fatal("BlindIndex disagrees with the oracle")
		}
	}
}

// A 1 MiB context: the additional data is long, the length prefix still counts
// bytes, and changing the very last byte of the context is enough to refuse.
func TestHostile_Differential_aMegabyteContext(t *testing.T) {
	d := newDeployment(t)
	context := randomBytes(t, 1<<20)
	f := d.column(context)
	o := newOracle(t, d.pepper, context)

	ct, err := f.Encrypt("v")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := o.open(ct); !ok || got != "v" {
		t.Fatal("the oracle cannot open a ciphertext bound to a 1 MiB context")
	}
	last := []byte(context)
	last[len(last)-1] ^= 1
	if got, err := d.column(string(last)).Decrypt(ct); got != "" || err != field.ErrDecrypt {
		t.Errorf("a context differing in its last byte opened the value: %q, %v", got, err)
	}
	if mustIndex(t, f, "v") != o.blindIndex("v") {
		t.Error("BlindIndex disagrees with the oracle for a 1 MiB context")
	}
}
