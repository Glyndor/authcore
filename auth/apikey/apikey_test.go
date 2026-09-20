package apikey_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
)

// ---- test infrastructure ----------------------------------------------------

type fakeKeys struct{ secret []byte }

func (fakeKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (fakeKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k fakeKeys) RefreshSecret() []byte        { return k.secret }
func (fakeKeys) KeyID() string                  { return "test" }

type fakeProvider struct{ keys authcore.Keys }

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p fakeProvider) Keys() authcore.Keys   { return p.keys }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(tb testing.TB, cfg ...apikey.Config) *apikey.APIKey {
	tb.Helper()
	p := fakeProvider{keys: fakeKeys{secret: []byte("0123456789abcdef0123456789abcdef")}}
	m, err := apikey.New(p, cfg...)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return m
}

// ---- New --------------------------------------------------------------------

// TestNew_defaultPrefix pins the documented default. The previous version
// of this test asserted only that Name() returned "apikey", which is also
// what TestName and the module wiring already pin. The actual contract
// being tested is "no Config => prefix 'ak'", so the test generates a key
// and asserts the prefix on the emitted string. A sabotage that swaps
// the default to something else (or removes the defaulting pass entirely)
// fails this test because Generate keys under the actual prefix the module
// was built with.
func TestNew_defaultPrefix(t *testing.T) {
	m := newMod(t)
	key, err := m.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(key.Key, "ak_") {
		t.Errorf("default prefix: key %q does not start with %q", key.Key, "ak_")
	}
}

func TestNew_invalidPrefixRejected(t *testing.T) {
	p := fakeProvider{keys: fakeKeys{secret: make([]byte, 32)}}
	for _, prefix := range []string{"has_underscore", "UPPER", "with space", strings.Repeat("x", 17)} {
		if _, err := apikey.New(p, apikey.Config{Prefix: prefix}); !errors.Is(err, apikey.ErrInvalidConfig) {
			t.Errorf("prefix %q: expected ErrInvalidConfig, got %v", prefix, err)
		}
	}
}

// ---- Generate / Verify ------------------------------------------------------

func TestGenerate_shapeAndVerify(t *testing.T) {
	m := newMod(t)
	key, err := m.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(key.Key, "ak_") {
		t.Errorf("key %q missing prefix", key.Key)
	}
	if parts := strings.Split(key.Key, "_"); len(parts) != 3 {
		t.Errorf("key has %d parts, want 3", len(parts))
	}
	id, err := m.ParseID(key.Key)
	if err != nil {
		t.Fatalf("ParseID: %v", err)
	}
	if id != key.ID {
		t.Errorf("ParseID = %q, want embedded ID %q", id, key.ID)
	}
	if !m.Verify(key.Key, key.Hash) {
		t.Error("Verify rejected a freshly generated key")
	}
}

func TestGenerate_uniquePerCall(t *testing.T) {
	m := newMod(t)
	a, _ := m.Generate()
	b, _ := m.Generate()
	if a.Key == b.Key || a.ID == b.ID || a.Hash == b.Hash {
		t.Error("two Generate calls produced colliding output")
	}
}

func TestVerify_wrongKeyRejected(t *testing.T) {
	m := newMod(t)
	key, _ := m.Generate()
	if m.Verify("ak_"+strings.Repeat("0", 32)+"_tampered", key.Hash) {
		t.Error("Verify accepted a key that does not match the stored hash")
	}
}

func TestVerify_peppered(t *testing.T) {
	// A hash made under one server secret must not verify under another.
	m1 := newMod(t)
	key, _ := m1.Generate()

	p2 := fakeProvider{keys: fakeKeys{secret: []byte("ffffffffffffffffffffffffffffffff")}}
	m2, _ := apikey.New(p2)
	if m2.Verify(key.Key, key.Hash) {
		t.Error("a key verified under a different server secret; HMAC pepper is not applied")
	}
}

func TestHash_deterministic(t *testing.T) {
	m := newMod(t)
	key, _ := m.Generate()
	recomputed, err := m.Hash(key.Key)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if recomputed != key.Hash {
		t.Error("Hash is not deterministic for the same key")
	}
}

// ---- ParseID ----------------------------------------------------------------

func TestParseID_malformedRejected(t *testing.T) {
	m := newMod(t)
	const hex32 = "0123456789abcdef0123456789abcdef"
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []string{
		"",
		"nope",
		"ak_onlytwo",
		"wrong_" + hex32 + "_" + hex64,
		"ak_" + strings.Repeat("z", 32) + "_" + hex64, // non-hex id
		"ak_" + strings.Repeat("0", 10) + "_" + hex64, // short id
		"ak_" + hex32 + "_",                           // empty secret
		"ak_" + hex32 + "_" + strings.Repeat("0", 63), // short secret
		"ak_" + hex32 + "_" + hex64 + "_extra",        // trailing field
		"ak_" + hex32 + "_" + strings.Repeat("z", 64), // non-hex secret
	}
	for _, c := range cases {
		if _, err := m.ParseID(c); !errors.Is(err, apikey.ErrInvalidKey) {
			t.Errorf("ParseID(%q) = %v, want ErrInvalidKey", c, err)
		}
	}
}

// TestParseID_rejectsShortSecret is the named test for the 64-hex secret
// requirement. A secret one byte shorter than the required length is
// rejected: the only well-formed secret length is exactly 64 lowercase hex
// characters, so a key minted by Generate is the only kind that survives.
func TestParseID_rejectsShortSecret(t *testing.T) {
	m := newMod(t)
	short := strings.Repeat("0", 63) // one hex char short
	key := "ak_" + strings.Repeat("0", 32) + "_" + short
	id, err := m.ParseID(key)
	if !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("ParseID(short secret) = (%q, %v), want (\"\", ErrInvalidKey)", id, err)
	}
	if id != "" {
		t.Errorf("ParseID(short secret) id = %q, want empty", id)
	}
}

// TestParseID_rejectsNonHexSecret is the named test for the lowercase-hex
// requirement on the secret. A secret of the right length that contains a
// non-hex character is rejected. Acceptance twin: a key from Generate
// parses with the same id it was minted with.
func TestParseID_rejectsNonHexSecret(t *testing.T) {
	m := newMod(t)
	bad := strings.Repeat("z", 64) // 64 chars, none of them hex
	key := "ak_" + strings.Repeat("0", 32) + "_" + bad
	id, err := m.ParseID(key)
	if !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("ParseID(non-hex secret) = (%q, %v), want (\"\", ErrInvalidKey)", id, err)
	}
	if id != "" {
		t.Errorf("ParseID(non-hex secret) id = %q, want empty", id)
	}

	// Acceptance pair: a freshly generated key is the only shape that
	// survives ParseID.
	issued, err := m.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	gotID, err := m.ParseID(issued.Key)
	if err != nil {
		t.Fatalf("ParseID(generated key): %v", err)
	}
	if gotID != issued.ID {
		t.Errorf("ParseID(generated key) = %q, want embedded id %q", gotID, issued.ID)
	}
}

// TestParseID_rejectsExtraField is the named test for the no-trailing-field
// requirement. A key with an extra separator and a fourth field is rejected,
// even when every other field has the right shape. The id returned is
// empty: ParseID never returns a partial answer on failure.
func TestParseID_rejectsExtraField(t *testing.T) {
	m := newMod(t)
	const hex32 = "0123456789abcdef0123456789abcdef"
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key := "ak_" + hex32 + "_" + hex64 + "_extra"
	id, err := m.ParseID(key)
	if !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("ParseID(extra field) = (%q, %v), want (\"\", ErrInvalidKey)", id, err)
	}
	if id != "" {
		t.Errorf("ParseID(extra field) id = %q, want empty", id)
	}
}

func TestParseID_customPrefix(t *testing.T) {
	m := newMod(t, apikey.Config{Prefix: "svc"})
	key, _ := m.Generate()
	if !strings.HasPrefix(key.Key, "svc_") {
		t.Errorf("custom prefix not applied: %q", key.Key)
	}
	if _, err := m.ParseID(key.Key); err != nil {
		t.Errorf("ParseID with custom prefix: %v", err)
	}
}
