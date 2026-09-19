package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/Glyndor/authcore"
)

// ---- test infrastructure ----------------------------------------------------

// fakeProvider satisfies authcore.Provider with a silent logger and no keys.
type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Password {
	t.Helper()
	mod, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return mod
}

// ---- New() ------------------------------------------------------------------

func TestNew_noArgsUsesDefaults(t *testing.T) {
	_, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New() with no config error = %v", err)
	}
}

func TestNew_explicitConfigSucceeds(t *testing.T) {
	_, err := New(fakeProvider{}, DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_zeroConfigSucceedsBecauseDefaultsAreApplied(t *testing.T) {
	_, err := New(fakeProvider{}, Config{})
	if err != nil {
		t.Fatalf("New(Config{}) error = %v; applyDefaults should have filled zero values", err)
	}
}

func TestNew_tooLowMemoryReturnsErrInvalidConfig(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: 1024}) // below 8 MiB minimum
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_zeroIterationsAreFilledByDefaults(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: DefaultConfig().Memory, Parallelism: 2})
	if err != nil {
		t.Fatalf("expected nil error when Iterations=0, got %v", err)
	}
}

func TestNew_zeroParallelismIsFilledByDefaults(t *testing.T) {
	_, err := New(fakeProvider{}, Config{Memory: DefaultConfig().Memory, Iterations: 1})
	if err != nil {
		t.Fatalf("expected nil error when Parallelism=0, got %v", err)
	}
}

// ---- Name() -----------------------------------------------------------------

func TestName(t *testing.T) {
	mod := newMod(t)
	if mod.Name() != "password" {
		t.Errorf("Name() = %q, want %q", mod.Name(), "password")
	}
}

// ---- Hash() -----------------------------------------------------------------

func TestHash_returnsPHCFormat(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=") {
		t.Errorf("Hash() = %q, expected PHC prefix $argon2id$v=", hash)
	}
}

func TestHash_saltIsRandom(t *testing.T) {
	mod := newMod(t)
	h1, err := mod.Hash("Same-Password9!")
	if err != nil {
		t.Fatalf("Hash() first call error = %v", err)
	}
	h2, err := mod.Hash("Same-Password9!")
	if err != nil {
		t.Fatalf("Hash() second call error = %v", err)
	}
	if h1 == h2 {
		t.Error("two Hash() calls with the same password produced identical output — salt is not random")
	}
}

func TestHash_embedsConfigParams(t *testing.T) {
	mod, err := New(fakeProvider{}, Config{Memory: 16 * 1024, Iterations: 2, Parallelism: 1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	hash, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if !strings.Contains(hash, "m=16384,t=2,p=1") {
		t.Errorf("Hash() = %q, expected to contain m=16384,t=2,p=1", hash)
	}
}

// ---- Verify() ---------------------------------------------------------------

func TestVerify_correctPassword(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("My-Secret-Pass9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("My-Secret-Pass9!", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false for the correct password, want true")
	}
}

func TestVerify_unicodeNFDInputMatchesNFCHash(t *testing.T) {
	mod := newMod(t)

	// Register with precomposed "é" (U+00E9) — the NFC form typically
	// produced by macOS and most IMEs.
	precomposed := "Contraseña-Seguro9!" // "ñ" as single codepoint U+00F1
	hash, err := mod.Hash(precomposed)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Log back in with the same password typed on a system that uses the
	// NFD decomposed form: "n" + combining tilde (U+006E U+0303). Without
	// NFC normalisation at Verify time the bytes differ → Argon2id hash
	// differs → user locked out. With normalisation, they match.
	decomposed := strings.ReplaceAll(precomposed, "ñ", "n\u0303")
	if decomposed == precomposed {
		t.Fatalf("test setup error: decomposed form is identical to input")
	}

	ok, err := mod.Verify(decomposed, hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false for NFD form of the same password, want true — NFC normalisation missing")
	}
}

func TestVerify_wrongPassword(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("My-Secret-Pass9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("Wrong-Password9!", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true for a wrong password, want false")
	}
}

func TestVerify_emptyPasswordDoesNotMatch(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true for empty password, want false")
	}
}

func TestVerify_malformedHashReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)

	_, err := mod.Verify("password", "not-a-phc-string")
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_wrongAlgorithmReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)
	wrongAlg := "$bcrypt$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZWtleQ"

	_, err := mod.Verify("password", wrongAlg)
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_usesParamsFromStoredHash(t *testing.T) {
	// Hash with low-cost config (fast for tests).
	hashMod, err := New(fakeProvider{}, Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatalf("New(lowCost) error = %v", err)
	}

	hash, err := hashMod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Verify with a different module config — must still succeed because Verify
	// reads the parameters from the stored hash, not from the module's Config.
	verifyMod := newMod(t) // uses DefaultConfig (64 MiB / 3 iterations)
	ok, err := verifyMod.Verify("Correct-Horse-9!", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false; stored hash should be verifiable even when module config differs")
	}
}

// ---- Hash() — policy enforcement --------------------------------------------

func TestHash_weakPasswordReturnsErrWeakPassword(t *testing.T) {
	mod := newMod(t)

	cases := []struct {
		name string
		pwd  string
	}{
		{"too short", "Aa1!"},
		{"too long", "Aa1!" + strings.Repeat("x", 61)},
		{"no uppercase", "lowercase1!aaa"},
		{"no lowercase", "UPPERCASE1!AAA"},
		{"no digit", "NoDigitHere!!!"},
		{"no special", "NoSpecial1Abcde"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mod.Hash(tc.pwd)
			if !errors.Is(err, ErrWeakPassword) {
				t.Errorf("Hash(%q) error = %v, want ErrWeakPassword", tc.pwd, err)
			}
		})
	}
}

func TestHash_strongPasswordSucceeds(t *testing.T) {
	mod := newMod(t)
	_, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Errorf("Hash(strong password) error = %v, want nil", err)
	}
}

// ---- checkPolicy() ----------------------------------------------------------

func TestCheckPolicy_boundaryLengths(t *testing.T) {
	base := "Aa1!"         // 4-char valid seed - pad to reach target length
	cfg := DefaultConfig() // 12..64, all classes required

	exactly12 := base + strings.Repeat("a", 8)
	if err := checkPolicy(exactly12, cfg); err != nil {
		t.Errorf("12-char password rejected: %v", err)
	}

	exactly64 := base + strings.Repeat("a", 60)
	if err := checkPolicy(exactly64, cfg); err != nil {
		t.Errorf("64-char password rejected: %v", err)
	}

	tooShort := base + strings.Repeat("a", 7) // 11 chars
	if checkPolicy(tooShort, cfg) == nil {
		t.Error("11-char password should be rejected")
	}

	tooLong := base + strings.Repeat("a", 61) // 65 chars
	if checkPolicy(tooLong, cfg) == nil {
		t.Error("65-char password should be rejected")
	}
}

// ---- ValidatePolicy() -------------------------------------------------------

func TestValidatePolicy_validPassword(t *testing.T) {
	p, _ := New(fakeProvider{})
	if err := p.ValidatePolicy("Correct-Horse-9!"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidatePolicy_weakPassword(t *testing.T) {
	p, _ := New(fakeProvider{})
	if err := p.ValidatePolicy("weak"); err == nil {
		t.Error("expected error for weak password, got nil")
	}
}

func TestValidatePolicy_nfcAndNfdFormsAgree(t *testing.T) {
	p, _ := New(fakeProvider{})

	// Same logical password in NFC (precomposed "é") and NFD (base "e" +
	// combining acute). Both byte sequences represent the same visual
	// password, so ValidatePolicy must treat them identically — accepting
	// or rejecting both the same way. Before NFC normalisation was added,
	// byte-level length counts and codepoint-level iteration could diverge
	// on these two forms.
	nfc := "Contraseña-Seguro9!"       // "ñ" as single codepoint U+00F1
	nfd := "Contrasen\u0303a-Seguro9!" // "ñ" as "n" + combining tilde U+0303

	if nfc == nfd {
		t.Fatal("test setup error: NFC and NFD forms are identical")
	}
	errNFC := p.ValidatePolicy(nfc)
	errNFD := p.ValidatePolicy(nfd)
	if (errNFC == nil) != (errNFD == nil) {
		t.Errorf("ValidatePolicy disagrees between NFC and NFD forms: NFC=%v, NFD=%v", errNFC, errNFD)
	}
}

// ---- parsePHC() -------------------------------------------------------------

func TestParsePHC_wrongSegmentCount(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=19$m=65536,t=3,p=2$onlyfour")
	if err == nil {
		t.Error("expected error for wrong segment count, got nil")
	}
}

func TestParsePHC_unparsableVersion(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=abc$m=65536,t=3,p=2$c2FsdA$a2V5")
	if err == nil {
		t.Error("expected error for unparsable version, got nil")
	}
}

func TestParsePHC_unsupportedVersion(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$a2V5")
	if err == nil {
		t.Error("expected error for unsupported Argon2 version, got nil")
	}
}

func TestParsePHC_unparsableParams(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=19$invalid$c2FsdA$a2V5")
	if err == nil {
		t.Error("expected error for unparsable parameters, got nil")
	}
}

func TestParsePHC_invalidBase64Salt(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=19$m=65536,t=3,p=2$!!!notbase64!!!$a2V5")
	if err == nil {
		t.Error("expected error for invalid base64 salt, got nil")
	}
}

func TestParsePHC_invalidBase64Key(t *testing.T) {
	_, _, _, err := parsePHC("$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!notbase64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 key, got nil")
	}
}

func TestParsePHC_memoryAboveCeilingRejected(t *testing.T) {
	// A corrupted or attacker-supplied hash with m=4_000_000_000 would cause
	// argon2.IDKey to attempt a multi-TiB allocation and crash the process.
	// The parser must reject it before the key derivation runs.
	//
	// The salt and key have to be well formed for this to be a test of the
	// memory ceiling. This used to pass the literal salt "c2FsdA", which is
	// four bytes, so the hash was refused by the salt-length check and the
	// test stayed green with the ceiling deleted. The comment above named a
	// control the body did not reach.
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, maxMemory+1, 3, 1))
	if err == nil {
		t.Fatal("expected error for memory above ceiling, got nil")
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Fatalf("refused for the wrong reason, so this is not a test of the ceiling: %v", err)
	}
}

func TestParsePHC_memoryBelowFloorRejected(t *testing.T) {
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, minMemory-1, 3, 1))
	if err == nil {
		t.Fatal("expected error for memory below floor, got nil")
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestParsePHC_iterationsAboveCeilingRejected(t *testing.T) {
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, minMemory, maxIterations+1, 1))
	if err == nil {
		t.Fatal("expected error for iterations above ceiling, got nil")
	}
	if !strings.Contains(err.Error(), "iterations") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestParsePHC_iterationsZeroRejected(t *testing.T) {
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, minMemory, 0, 1))
	if err == nil {
		t.Fatal("expected error for zero iterations, got nil")
	}
	if !strings.Contains(err.Error(), "iterations") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestParsePHC_parallelismZeroRejected(t *testing.T) {
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version, minMemory, 3, 0))
	if err == nil {
		t.Fatal("expected error for zero parallelism, got nil")
	}
	if !strings.Contains(err.Error(), "parallelism") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestVerify_malformedStoredHashIsRejectedBeforeKeyDerivation(t *testing.T) {
	p := newMod(t)

	// If Verify accepted this hash, argon2.IDKey would try to allocate 4 TiB.
	// parsePHC must surface ErrInvalidHash instead.
	//
	// The salt and key are well formed on purpose, so the memory ceiling is
	// the only thing left that can refuse this. With the four-byte salt this
	// used to carry, the salt-length check refused it first and the test
	// stayed green with the ceiling deleted.
	malicious := phc(t, "argon2id", argon2.Version, maxMemory+1, 3, 1)
	_, err := p.Verify("any-password-we-do-not-care", malicious)
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash for malicious stored hash, got %v", err)
	}
}

func TestVerify_emptyKeySegmentRejectedNotPanic(t *testing.T) {
	p := newMod(t)

	// A truncated hash with an empty key segment reaches argon2.IDKey with
	// keyLen=0, which panics (nil dereference) and crashes the process.
	// parsePHC must reject it as ErrInvalidHash, never derive a key.
	cases := map[string]string{
		"empty key":  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$",
		"empty salt": "$argon2id$v=19$m=65536,t=3,p=2$$" + strings.Repeat("A", 43),
		"short key":  "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$a2V5",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := p.Verify("any-password-we-do-not-care", h)
			if ok {
				t.Fatalf("%s: malformed hash must never verify true", name)
			}
			if !errors.Is(err, ErrInvalidHash) {
				t.Errorf("%s: expected ErrInvalidHash, got %v", name, err)
			}
		})
	}
}

// ---- DefaultConfig() --------------------------------------------------------

func TestDefaultConfig_values(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Memory != 64*1024 {
		t.Errorf("DefaultConfig().Memory = %d, want %d", cfg.Memory, 64*1024)
	}
	if cfg.Iterations != 3 {
		t.Errorf("DefaultConfig().Iterations = %d, want 3", cfg.Iterations)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("DefaultConfig().Parallelism = %d, want 2", cfg.Parallelism)
	}
}

// ---- applyDefaults() --------------------------------------------------------

func TestApplyDefaults_fillsZeroMemory(t *testing.T) {
	cfg := applyDefaults(Config{Iterations: 1, Parallelism: 1})
	if cfg.Memory != DefaultConfig().Memory {
		t.Errorf("applyDefaults zero Memory = %d, want %d", cfg.Memory, DefaultConfig().Memory)
	}
}

func TestApplyDefaults_fillsZeroIterations(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Parallelism: 1})
	if cfg.Iterations != DefaultConfig().Iterations {
		t.Errorf("applyDefaults zero Iterations = %d, want %d", cfg.Iterations, DefaultConfig().Iterations)
	}
}

func TestApplyDefaults_fillsZeroParallelism(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Iterations: 1})
	if cfg.Parallelism != DefaultConfig().Parallelism {
		t.Errorf("applyDefaults zero Parallelism = %d, want %d", cfg.Parallelism, DefaultConfig().Parallelism)
	}
}
