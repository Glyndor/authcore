package password

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

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

func TestVerify_rejectsLeadingGarbage(t *testing.T) {
	mod := newMod(t)

	const pw = "Correct-Horse-9!"
	clean, err := mod.Hash(pw)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Acceptance pair: the clean hash must still verify, so this is a test of
	// the prefix check rather than a regression that turned the whole parser
	// against every hash.
	ok, err := mod.Verify(pw, clean)
	if err != nil || !ok {
		t.Fatalf("clean hash must still verify: ok=%v err=%v", ok, err)
	}

	ok, err = mod.Verify(pw, "junk"+clean)
	if ok {
		t.Errorf("Verify with junk-prefixed PHC must not succeed, got ok=true")
	}
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("Verify with junk-prefixed PHC: expected ErrInvalidHash, got %v", err)
	}
}

func TestParsePHC_rejectsTrailingTextInFields(t *testing.T) {
	clean := phc(t, "argon2id", argon2.Version, minMemory, 3, 1)

	if _, _, _, err := parsePHC(clean); err != nil {
		t.Fatalf("clean fixture must parse, otherwise the rejections below prove nothing: %v", err)
	}

	// Swap "v=19" for "v=19junk" and verify the parser refuses it. fmt.Sscanf
	// used to bind v to 19 and ignore the suffix, so the rest of the parser
	// proceeded with a value that the surrounding string did not actually
	// contain.
	badVersion := strings.Replace(clean, "v="+itoa(argon2.Version), "v="+itoa(argon2.Version)+"junk", 1)
	if _, _, _, err := parsePHC(badVersion); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("v=19junk: expected ErrInvalidHash, got %v", err)
	}

	// Same shape, this time in the m= field of the parameter segment.
	badMemory := strings.Replace(clean, "m="+itoa(minMemory), "m="+itoa(minMemory)+"junk", 1)
	if _, _, _, err := parsePHC(badMemory); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("m=%djunk: expected ErrInvalidHash, got %v", minMemory, err)
	}
}

// itoa formats n in base 10. strconv.Itoa would do, but keeping the helper
// local makes the test self-contained.
func itoa(n int) string { return strconv.Itoa(n) }

func TestVerify_wrongAlgorithmReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)

	// The fixture uses the phc() helper, which gives a salt and key of the
	// exact lengths parsePHC requires. The four-byte salt the previous
	// fixture carried was what made the test green with the algorithm
	// check removed: parsePHC refused on salt length first and never
	// reached the algorithm. With valid salt and key, removing the
	// algorithm check lets the bcrypt-shaped hash pass into argon2.IDKey
	// and the test no longer catches the sabotage.
	wrongAlg := phc(t, "bcrypt", argon2.Version, minMemory, 3, 1)

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

// TestValidatePolicy_lengthBoundaryStraddlesNFCAndNFD pins the normalisation
// at the length boundary. With a length-only policy (12..64 runes, no class
// requirements), a password of 64 precomposed "ñ" characters is 64 runes in
// NFC and at the cap. The same visual password written with one of those
// characters in NFD ("n" + combining tilde) is 65 runes without
// normalisation, over the cap, and 64 runes after normalisation. Without
// NFC normalisation the policy would reject the NFD form even though the
// NFC form passes, the bug a caller from a system that produces decomposed
// text would hit on the first attempt to register.
//
// The acceptance twin: the NFC form must also pass, otherwise a test that
// rejected both forms would still be a pass.
func TestValidatePolicy_lengthBoundaryStraddlesNFCAndNFD(t *testing.T) {
	// Length-only policy: the class requirements would otherwise force the
	// fixture to include an uppercase letter, a lowercase letter, a digit
	// and a symbol, none of which matters for the boundary being tested.
	off := false
	cfg := DefaultConfig()
	cfg.MinLength = 12
	cfg.MaxLength = 64
	cfg.RequireUpper = &off
	cfg.RequireLower = &off
	cfg.RequireDigit = &off
	cfg.RequireSymbol = &off

	p, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 64 precomposed ñ: exactly 64 runes in NFC, at the cap.
	nfcAtCap := strings.Repeat("ñ", 64)
	if utf8.RuneCountInString(nfcAtCap) != 64 {
		t.Fatalf("test setup: NFC fixture should be 64 runes, got %d", utf8.RuneCountInString(nfcAtCap))
	}
	if err := p.ValidatePolicy(nfcAtCap); err != nil {
		t.Fatalf("64-rune NFC ñ-chain should be at the cap and accepted, got %v", err)
	}

	// 63 precomposed ñ plus one decomposed ñ: 63 + 2 = 65 runes without
	// normalisation, which would be refused; 63 + 1 = 64 runes after
	// normalisation, which is at the cap and must be accepted.
	nfdOverCap := strings.Repeat("ñ", 63) + "n\u0303"
	if got := utf8.RuneCountInString(nfdOverCap); got != 65 {
		t.Fatalf("test setup: expected 65 runes before normalisation, got %d", got)
	}
	if err := p.ValidatePolicy(nfdOverCap); err != nil {
		t.Errorf("NFD form over the rune cap before normalisation must pass after NFC normalisation, got %v", err)
	}

	// Acceptance twin: the NFD form, after explicit NFC normalisation, is
	// still 64 runes and still passes, so the policy is unchanged when the
	// input already happens to be NFC.
	if err := p.ValidatePolicy(norm.NFC.String(nfdOverCap)); err != nil {
		t.Errorf("explicitly NFC-normalised form should be accepted too, got %v", err)
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
	// Valid salt and key, only the version is wrong. The four-byte salt the
	// previous fixture carried was refused before the version check could
	// fire, so a version check deletion stayed green.
	_, _, _, err := parsePHC(phc(t, "argon2id", argon2.Version-1, minMemory, 3, 1))
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
