package kdf_test

import (
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/password"
)

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
	mod, err := password.New(fakeProvider{}, password.Config{Memory: 16 * 1024, Iterations: 2, Parallelism: 1})
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

func TestVerify_usesParamsFromStoredHash(t *testing.T) {
	// Hash with low-cost config (fast for tests).
	hashMod, err := password.New(fakeProvider{}, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
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

// Controls the 2026-09-25 review found working but unpinned: each could be
// deleted with the package suite green. Every test names what its control
// holds, and the acceptance case sits next to the refusal.

const nfdPassword = "Café-Espresso-99" // "é" as e + combining acute

// Hash normalises to NFC before hashing, as Verify does before comparing.
// Without it a user who registers with a decomposed password never signs
// in with the same input. The suite only covered NFC-hash, NFD-verify.
func TestHash_normalisesTheInputItHashes(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash(nfdPassword)
	if err != nil {
		t.Fatalf("Hash(NFD): %v", err)
	}
	for name, input := range map[string]string{"the NFD form": nfdPassword, "the NFC form": norm.NFC.String(nfdPassword)} {
		ok, err := mod.Verify(input, hash)
		if err != nil || !ok {
			t.Errorf("Verify(%s) = %v, %v; want true", name, ok, err)
		}
	}
	if ok, _ := mod.Verify("Cafe-Espresso-99", hash); ok {
		t.Fatal("a different password verified")
	}
}
