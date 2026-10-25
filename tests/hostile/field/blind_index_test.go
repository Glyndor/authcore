package field_test

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/username"
)

// The blind index is HMAC-SHA256 under a key derived from the pepper with its
// own label, over the length-prefixed context and value. An independent
// implementation reproduces it. That fixes three things a self-comparing test
// cannot: the index key is not the encryption key, the context is part of the
// input, and the fields are length-prefixed.
func TestHostile_BlindIndex_matchesAnIndependentOracle(t *testing.T) {
	d := newDeployment(t)
	idxKey, err := hkdf.Key(sha256.New, d.pepper, nil, "authcore/field/blind-index/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	oracle := func(context, value string) string {
		mac := hmac.New(sha256.New, idxKey)
		for _, s := range []string{context, value} {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(s)))
			mac.Write(n[:])
			mac.Write([]byte(s))
		}
		return hex.EncodeToString(mac.Sum(nil))
	}
	for _, tc := range [][2]string{
		{"users.email", "alice@example.com"},
		{"users.email", ""},
		{"c", "\x00"},
		{"users.email", strings.Repeat("a", 1<<20)},
		{"\u00fcsers", "\u00e9"},
	} {
		got, err := d.column(tc[0]).BlindIndex(tc[1])
		if err != nil || got != oracle(tc[0], tc[1]) {
			t.Errorf("BlindIndex(%q, %.20q) = %q, %v; want %q", tc[0], tc[1], got, err, oracle(tc[0], tc[1]))
		}
	}
}

// The index of a value differs between columns, between deployments, and for
// every pair of distinct values; equal inputs always give equal indexes.
func TestHostile_BlindIndex_separatesColumnsDeploymentsAndValues(t *testing.T) {
	d := newDeployment(t)
	email, phone := d.column("users.email"), d.column("users.phone")
	idx := func(f interface{ BlindIndex(string) (string, error) }, v string) string {
		h, err := f.BlindIndex(v)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	first, second := idx(email, "x"), idx(email, "x")
	if first != second {
		t.Fatal("the index is not deterministic")
	}
	if idx(email, "x") == idx(phone, "x") {
		t.Error("two columns indexed one value identically: an equality join across columns leaks")
	}
	if idx(email, "x") == idx(newDeployment(t).column("users.email"), "x") {
		t.Error("two deployments indexed one value identically")
	}

	// Context and value are length-prefixed, so moving bytes between them
	// changes the index.
	ab, a := d.column("ab"), d.column("a")
	if idx(ab, "c") == idx(a, "bc") {
		t.Error("the context/value boundary can be shifted")
	}
	if idx(d.column("a\x00"), "") == idx(d.column("a"), "\x00") {
		t.Error("a NUL moved across the boundary kept the index")
	}

	seen := map[string]string{}
	for i := 0; i < 100000; i++ {
		v := fmt.Sprintf("user-%d@example.com", i)
		h := idx(email, v)
		if len(h) != 64 {
			t.Fatalf("index is %d characters", len(h))
		}
		if prev, dup := seen[h]; dup {
			t.Fatalf("%q and %q share an index", prev, v)
		}
		seen[h] = v
	}
}

// The module does not normalise, by design: a different spelling is a different
// index. What the application relies on is that the normalising modules reduce
// every spelling of one address to one string, so one address cannot hold two
// accounts, and that lookalikes the normalisers do not fold stay distinct
// rather than silently merging two different people.
func TestHostile_BlindIndex_spellingsOfOneAddressMeetAtTheNormalisedForm(t *testing.T) {
	d := newDeployment(t)
	f := d.column("users.email")
	prov := d.prov
	em, err := email.New(prov)
	if err != nil {
		t.Fatal(err)
	}
	index := func(addr string) string {
		n, err := em.ValidateAndNormalize(addr)
		if err != nil {
			t.Fatalf("%q: %v", addr, err)
		}
		h, _ := f.BlindIndex(n)
		return h
	}

	want := index("alice@example.com")
	for _, spelling := range []string{
		"Alice@Example.COM",
		"  alice@example.com\t",
		"ALICE@EXAMPLE.COM",
		"alice@EXAMPLE.com\n",
	} {
		if got := index(spelling); got != want {
			t.Errorf("%q indexes differently from alice@example.com", spelling)
		}
	}

	// Raw, the module keeps them apart: the caller's normalisation is what
	// merges them.
	a, _ := f.BlindIndex("alice@example.com")
	b, _ := f.BlindIndex("Alice@example.com")
	if a == b {
		t.Error("the module normalised case itself, which its contract says it never does")
	}

	// Different people stay different.
	for _, other := range []string{"alice+tag@example.com", "alice@example.org", "alice2@example.com", "\u0430lice@example.com"} {
		if got := index(other); got == want {
			t.Errorf("%q collides with alice@example.com", other)
		}
	}

	// The same for usernames.
	un, _ := username.New(prov)
	ui := func(name string) string {
		n, err := un.ValidateAndNormalize(name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		h, _ := d.column("users.username").BlindIndex(n)
		return h
	}
	if ui("Alice") != ui("  alice ") || ui("ALICE") != ui("alice") {
		t.Error("spellings of one username index differently")
	}
	if ui("alice") == ui("alice2") {
		t.Error("two usernames share an index")
	}
}
