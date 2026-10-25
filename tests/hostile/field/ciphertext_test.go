package field_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/field"
)

const plaintext = "alice@example.com"

// A stored value is opened only by the module that sealed it: same pepper,
// same column context. Every other module, every re-spelled context and every
// other deployment gets the one uniform ErrDecrypt.
func TestHostile_Field_ciphertextIsBoundToContextAndKey(t *testing.T) {
	d := newDeployment(t)
	users := d.column("users.email")
	ct, err := users.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := users.Decrypt(ct); err != nil || got != plaintext {
		t.Fatalf("control: %q, %v", got, err)
	}

	for name, f := range map[string]*field.Field{
		"another column":      d.column("users.phone"),
		"case changed":        d.column("Users.email"),
		"trailing space":      d.column("users.email "),
		"prefix of context":   d.column("users.emai"),
		"context is a prefix": d.column("users.email2"),
		"single character":    d.column("u"),
		"unicode lookalike":   d.column("users.\u0435mail"),
		"NUL appended":        d.column("users.email\x00"),
		"another deployment":  newDeployment(t).column("users.email"),
	} {
		got, err := f.Decrypt(ct)
		if got != "" || err != field.ErrDecrypt {
			t.Errorf("%s: Decrypt = %q, %v; want empty and exactly ErrDecrypt", name, got, err)
		}
	}
}

// The ciphertext is AES-256-GCM under a key derived from the pepper, with the
// context as additional data. An independent implementation that uses only the
// documented derivation opens it and seals something the module opens, so the
// separation of the encryption key from the index key and the binding to the
// context are real and not a property of this code reading itself.
func TestHostile_Field_matchesAnIndependentAESGCMOracle(t *testing.T) {
	d := newDeployment(t)
	const context = "users.email"
	f := d.column(context)

	encKey, err := hkdf.Key(sha256.New, d.pepper, nil, "authcore/field/aes-256-gcm/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(encKey)
	gcm, _ := cipher.NewGCM(block)
	aad := make([]byte, 4, 4+len(context))
	binary.BigEndian.PutUint32(aad, uint32(len(context)))
	aad = append(aad, context...)

	ct, _ := f.Encrypt(plaintext)
	raw, err := base64.RawStdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 12+len(plaintext)+16 {
		t.Fatalf("sealed value is %d bytes, want nonce(12)+plaintext(%d)+tag(16)", len(raw), len(plaintext))
	}
	opened, err := gcm.Open(nil, raw[:12], raw[12:], aad)
	if err != nil || string(opened) != plaintext {
		t.Fatalf("the independent oracle could not open the module's ciphertext: %q, %v", opened, err)
	}

	nonce := make([]byte, 12)
	sealed := gcm.Seal(nonce, nonce, []byte("sealed elsewhere"), aad)
	if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(sealed)); err != nil || got != "sealed elsewhere" {
		t.Fatalf("the module could not open the oracle's ciphertext: %q, %v", got, err)
	}

	// Sealed without the context in the additional data, the same bytes are
	// refused: the binding is enforced, not just recorded.
	bare := gcm.Seal(nonce, nonce, []byte("no aad"), nil)
	if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(bare)); got != "" || err != field.ErrDecrypt {
		t.Fatalf("a ciphertext without the context opened: %q, %v", got, err)
	}
}

// Flipping any single bit of the stored value, in the nonce, the ciphertext or
// the tag, makes it fail. GCM authenticates all of it.
func TestHostile_Field_everyBitFlipIsRefused(t *testing.T) {
	f := newDeployment(t).column("users.email")
	ct, _ := f.Encrypt(plaintext)
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	for i := range raw {
		for bit := 0; bit < 8; bit++ {
			mut := append([]byte(nil), raw...)
			mut[i] ^= 1 << bit
			got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(mut))
			if got != "" || err != field.ErrDecrypt {
				t.Fatalf("byte %d bit %d flipped: %q, %v", i, bit, got, err)
			}
		}
	}
}

// Every proper prefix of the stored value fails, and so does the value with
// bytes added. Truncating a ciphertext cannot yield a shorter plaintext.
func TestHostile_Field_truncationAndExtensionAreRefused(t *testing.T) {
	f := newDeployment(t).column("users.email")
	ct, _ := f.Encrypt(plaintext)
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	for n := 0; n < len(raw); n++ {
		if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(raw[:n])); got != "" || err != field.ErrDecrypt {
			t.Fatalf("a %d byte prefix: %q, %v", n, got, err)
		}
	}
	for _, extra := range [][]byte{{0}, {0, 0, 0, 0}, make([]byte, 16), make([]byte, 1<<16)} {
		longer := append(append([]byte(nil), raw...), extra...)
		if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(longer)); got != "" || err != field.ErrDecrypt {
			t.Fatalf("%d bytes appended: %q, %v", len(extra), got, err)
		}
	}
}

// The stored text has one spelling. Padding, other alphabets, whitespace and
// stray bits in the last character decode to the same bytes in lenient
// decoders, and each is refused here, so a value cannot be re-spelled to dodge
// a comparison on the stored text.
func TestHostile_Field_onlyTheCanonicalSpellingIsAccepted(t *testing.T) {
	f := newDeployment(t).column("users.email")
	// A 16 byte plaintext seals to 44 bytes, which is not a multiple of three,
	// so the standard encoding pads and the last character has unused bits.
	// The loop waits for a ciphertext with a "+" or "/" so the alphabet case
	// bites.
	var ct string
	for {
		ct, _ = f.Encrypt("alice@example.co")
		if strings.ContainsAny(ct, "+/") {
			break
		}
	}
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	cases := map[string]string{
		"empty":            "",
		"padded":           base64.StdEncoding.EncodeToString(raw),
		"url alphabet":     base64.RawURLEncoding.EncodeToString(raw),
		"leading space":    " " + ct,
		"trailing space":   ct + " ",
		"trailing newline": ct + "\n",
		"inner newline":    ct[:10] + "\n" + ct[10:],
		"inner space":      ct[:10] + " " + ct[10:],
		"trailing NUL":     ct + "\x00",
		"wrapped at 76":    ct[:20] + "\r\n" + ct[20:],
		"quoted":           `"` + ct + `"`,
		"doubled":          ct + ct,
		"hex":              strings.Repeat("ab", 40),
		"non-ASCII":        ct[:10] + "\u00e9" + ct[11:],
	}
	for name, v := range cases {
		if got, err := f.Decrypt(v); got != "" || err != field.ErrDecrypt {
			t.Errorf("%s: Decrypt = %q, %v; want empty and ErrDecrypt", name, got, err)
		}
	}

	// A value whose last character carries bits beyond the data: decoded
	// leniently it is the same bytes, so it must be refused.
	last := ct[len(ct)-1]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	idx := strings.IndexByte(alphabet, last)
	if len(raw)%3 != 0 {
		alt := alphabet[idx^1]
		if got, err := f.Decrypt(ct[:len(ct)-1] + string(alt)); got != "" || err != field.ErrDecrypt {
			t.Errorf("non-canonical last character accepted: %q, %v", got, err)
		}
	}
}

// Every failure is the same value. An observer who sees the error learns
// nothing about whether the text, the length, the tag or the context was wrong.
func TestHostile_Field_failuresAreOneUniformError(t *testing.T) {
	d := newDeployment(t)
	f := d.column("users.email")
	other := d.column("users.phone")
	ct, _ := f.Encrypt(plaintext)
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	tag := append([]byte(nil), raw...)
	tag[len(tag)-1] ^= 1

	for name, v := range map[string]string{
		"not base64": "!!!!",
		"too short":  "AAAA",
		"bad tag":    base64.RawStdEncoding.EncodeToString(tag),
		"wrong ctx":  func() string { c, _ := other.Encrypt(plaintext); return c }(),
		"empty":      "",
	} {
		_, err := f.Decrypt(v)
		if err != field.ErrDecrypt {
			t.Errorf("%s: err = %v (%T), want exactly field.ErrDecrypt", name, err, err)
		}
		if errors.Unwrap(err) != nil {
			t.Errorf("%s: the error wraps a cause: %v", name, errors.Unwrap(err))
		}
	}
}

// Nonces are fresh. Across a large batch, from one goroutine and from many,
// no nonce and no ciphertext repeats, even for identical plaintext. A repeated
// nonce under one key is the failure that breaks GCM.
func TestHostile_Field_nonceNeverRepeats(t *testing.T) {
	f := newDeployment(t).column("users.email")
	var mu sync.Mutex
	nonces, cts := map[string]bool{}, map[string]bool{}
	record := func(ct string) {
		raw, err := base64.RawStdEncoding.DecodeString(ct)
		if err != nil || len(raw) < 12 {
			t.Errorf("malformed ciphertext %q: %v", ct, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		n := string(raw[:12])
		if nonces[n] || cts[ct] {
			t.Errorf("a nonce or ciphertext repeated")
		}
		nonces[n], cts[ct] = true, true
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				ct, err := f.Encrypt(plaintext)
				if err != nil {
					t.Error(err)
					return
				}
				record(ct)
			}
		}()
	}
	wg.Wait()
	if len(nonces) != 8*5000 {
		t.Fatalf("%d distinct nonces for %d encryptions", len(nonces), 8*5000)
	}
}

// Hostile plaintexts round-trip byte for byte and hostile ciphertexts of any
// size are refused without cost to the host.
func TestHostile_Field_extremeSizesAndBytes(t *testing.T) {
	f := newDeployment(t).column("users.email")
	for name, p := range map[string]string{
		"empty":         "",
		"one byte":      "a",
		"NUL":           "\x00",
		"only NULs":     strings.Repeat("\x00", 4096),
		"invalid UTF-8": "\xff\xfe\xfd",
		"emoji":         "\U0001F600\u200d\U0001F600",
		"16 MiB":        strings.Repeat("x", 16<<20),
	} {
		ct, err := f.Encrypt(p)
		if err != nil {
			t.Errorf("%s: Encrypt: %v", name, err)
			continue
		}
		got, err := f.Decrypt(ct)
		if err != nil || got != p {
			t.Errorf("%s: round trip = %d bytes, %v; want %d bytes", name, len(got), err, len(p))
		}
	}

	for _, size := range []int{1 << 20, 8 << 20} {
		start := time.Now()
		if got, err := f.Decrypt(strings.Repeat("A", size)); got != "" || err != field.ErrDecrypt {
			t.Errorf("%d byte garbage: %q, %v", size, got[:min(len(got), 10)], err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%d byte garbage took %v to refuse", size, d)
		}
	}
}

// Construction and zero values.
func TestHostile_Field_constructionAndUninitialisedUse(t *testing.T) {
	prov := newProviderWithPepper(t, randomPepper(t))
	for name, cfg := range map[string]field.Config{"empty context": {}} {
		if _, err := field.New(prov, cfg); !errors.Is(err, field.ErrInvalidConfig) {
			t.Errorf("%s: field.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	for name, pepper := range map[string][]byte{"nil": nil, "empty": {}, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33)} {
		if _, err := field.New(newProviderWithPepper(t, pepper), field.Config{Context: "c"}); !errors.Is(err, field.ErrInvalidConfig) {
			t.Errorf("pepper %s: field.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := field.New(prov, field.Config{Context: "c"}, field.Config{Context: "d"}); !errors.Is(err, field.ErrInvalidConfig) {
		t.Errorf("two configs: %v", err)
	}

	zero := &field.Field{}
	if ct, err := zero.Encrypt("x"); ct != "" || !errors.Is(err, field.ErrNotInitialised) {
		t.Errorf("zero Encrypt: %q, %v", ct, err)
	}
	if p, err := zero.Decrypt("x"); p != "" || !errors.Is(err, field.ErrNotInitialised) {
		t.Errorf("zero Decrypt: %q, %v", p, err)
	}
	if h, err := zero.BlindIndex("x"); h != "" || !errors.Is(err, field.ErrNotInitialised) {
		t.Errorf("zero BlindIndex: %q, %v", h, err)
	}
}
