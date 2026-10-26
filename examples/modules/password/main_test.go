package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

const demoPassword = "Str0ng-P@ssword!"

// newModule builds the module the way the example does, with keys in a
// directory that is removed when the test ends.
func newModule(t *testing.T) *password.Password {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := password.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

// TestRunPrintsWhatTheReadmeShows runs the whole example.
func TestRunPrintsWhatTheReadmeShows(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rejected  :", "accepted  : " + demoPassword, "correct password : true", "wrong password   : false", "ErrInvalidHash caught correctly", "128 MiB hash: $argon2id$v=19$m=131072,t=4,p=4$"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// TestEmptyAndOversizedPasswordsAreRefusedBeforeHashing checks the two bounds
// the example relies on: no empty password, and a ceiling on length, because
// Argon2id reads every byte it is given.
func TestEmptyAndOversizedPasswordsAreRefusedBeforeHashing(t *testing.T) {
	mod := newModule(t)

	for name, pw := range map[string]string{
		"empty": "", "spaces": strings.Repeat(" ", 20), "one megabyte": strings.Repeat("Aa1!", 1<<18),
		"NUL inside": "Str0ng-P@ss\x00word!", "newline inside": "Str0ng-P@ss\nword!", "invalid UTF-8": "Str0ng-P@ss\xffword!",
	} {
		start := time.Now()
		err := mod.ValidatePolicy(pw)
		if !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%s: ValidatePolicy returned %v, want ErrWeakPassword", name, err)
		}
		if _, err := mod.Hash(pw); !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%s: Hash returned %v, want ErrWeakPassword", name, err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Errorf("%s: refusal took %v, it looks hashed", name, elapsed)
		}
	}
}

// TestPolicyReasonNeverEchoesThePassword checks the message the example says
// is safe to return in a 400.
func TestPolicyReasonNeverEchoesThePassword(t *testing.T) {
	mod := newModule(t)
	for _, pw := range []string{"secretword", "alllowercaseletters", "NoDigitsHere!!!!", "Sh0rt!"} {
		err := mod.ValidatePolicy(pw)
		if err == nil {
			continue
		}
		reason := errors.Unwrap(err)
		if reason == nil || strings.Contains(reason.Error(), pw) || strings.Contains(err.Error(), pw) {
			t.Errorf("password %q: reason %v echoes the input or is missing", pw, reason)
		}
	}
}

// TestVerifyUsage covers how a login handler uses Verify.
func TestVerifyUsage(t *testing.T) {
	mod := newModule(t)
	hash, err := mod.Hash(demoPassword)
	if err != nil {
		t.Fatal(err)
	}

	again, _ := mod.Hash(demoPassword)
	if hash == again {
		t.Error("two hashes of one password are identical: the salt is not random")
	}
	for _, h := range []string{hash, again} {
		if ok, err := mod.Verify(demoPassword, h); err != nil || !ok {
			t.Errorf("a hash of the password does not verify: %v %v", ok, err)
		}
	}

	for name, attempt := range map[string]string{
		"wrong": "WrongPassword1!", "empty": "", "prefix": demoPassword[:len(demoPassword)-1],
		"suffix": demoPassword + "x", "other case": strings.ToUpper(demoPassword), "padded": " " + demoPassword,
	} {
		if ok, err := mod.Verify(attempt, hash); ok || err != nil {
			t.Errorf("%s: Verify returned %v %v, want false and no error", name, ok, err)
		}
	}

	composed, decomposed := "Caf\u00e9-Passw0rd!", "Cafe\u0301-Passw0rd!"
	h, err := mod.Hash(composed)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := mod.Verify(decomposed, h); !ok {
		t.Error("the same password typed with a combining accent does not verify")
	}
}

// TestHostileStoredHashesAreRefused covers the "stored hash" input a database
// compromise or a corrupted row provides. Verify must return ErrInvalidHash,
// quickly, and never true.
func TestHostileStoredHashesAreRefused(t *testing.T) {
	mod := newModule(t)
	hash, _ := mod.Hash(demoPassword)

	bad := map[string]string{
		"empty": "", "not a hash": "not-a-valid-phc-string", "truncated": hash[:len(hash)/2],
		"argon2i":         strings.Replace(hash, "$argon2id$", "$argon2i$", 1),
		"4 GiB of memory": "$argon2id$v=19$m=4194304,t=20,p=255$" + strings.SplitN(hash, "$", 6)[4] + "$" + strings.SplitN(hash, "$", 6)[5],
		"zero memory":     "$argon2id$v=19$m=0,t=3,p=2$" + strings.SplitN(hash, "$", 6)[4] + "$" + strings.SplitN(hash, "$", 6)[5],
		"bcrypt":          "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
	}
	for name, h := range bad {
		start := time.Now()
		ok, err := mod.Verify(demoPassword, h)
		if ok || !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("%s: Verify returned %v %v, want false and ErrInvalidHash", name, ok, err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s: took %v, the stored hash steered the work", name, elapsed)
		}
	}
}

// TestCustomParametersStayVerifiable checks the claim of example 5: a hash
// made with heavier parameters verifies under a module with the defaults,
// because the parameters travel in the hash.
func TestCustomParametersStayVerifiable(t *testing.T) {
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	strong, err := password.New(auth, password.Config{Memory: 128 * 1024, Iterations: 4, Parallelism: 4})
	if err != nil {
		t.Fatal(err)
	}
	h, err := strong.Hash(demoPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h, "m=131072,t=4,p=4") {
		t.Fatalf("hash does not carry its parameters: %.40s", h)
	}
	if ok, err := newModule(t).Verify(demoPassword, h); err != nil || !ok {
		t.Errorf("the default module cannot verify a heavier hash: %v %v", ok, err)
	}
}
