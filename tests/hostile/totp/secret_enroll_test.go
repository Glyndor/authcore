package totp_test

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// A secret that is not exactly what Enroll writes (twenty random bytes in
// unpadded upper-case base32) is refused, so a stored secret that was
// truncated, re-cased, padded or reformatted cannot quietly verify against a
// shorter or different key.
func TestHostile_TOTP_malformedSecretsAreRefused(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	if len(secret) != 32 {
		t.Fatalf("test bug: secret is %d characters, want 32", len(secret))
	}
	atStableStep(t, func(step uint64) string {
		if _, err := m.VerifyStep(secret, codeAt(t, secret, step), 0); err != nil {
			return fmt.Sprintf("control: %v", err)
		}
		return ""
	})

	for name, s := range map[string]string{
		"empty":               "",
		"one character":       "A",
		"16 characters":       secret[:16],
		"31 characters":       secret[:31],
		"33 characters":       secret + "A",
		"40 characters":       secret + strings.Repeat("A", 8),
		"41 characters":       secret + strings.Repeat("A", 9),
		"one MiB":             strings.Repeat("A", 1<<20),
		"lower case":          strings.ToLower(secret),
		"mixed case":          secret[:16] + strings.ToLower(secret[16:]),
		"padded":              secret + "====",
		"trailing space":      secret + " ",
		"leading space":       " " + secret,
		"grouped by four":     strings.Join([]string{secret[:4], secret[4:8], secret[8:12], secret[12:16], secret[16:20], secret[20:24], secret[24:28], secret[28:]}, " "),
		"hyphenated":          secret[:16] + "-" + secret[16:],
		"digit 0":             "0" + secret[1:],
		"digit 1":             "1" + secret[1:],
		"digit 8":             "8" + secret[1:],
		"digit 9":             "9" + secret[1:],
		"NUL":                 secret[:10] + "\x00" + secret[11:],
		"newline":             secret + "\n",
		"fullwidth letter":    "\uff21" + secret[1:],
		"cyrillic lookalike":  "\u0410" + secret[1:],
		"url encoded":         url.QueryEscape(secret + "=="),
		"hex of the same key": strings.Repeat("ab", 20),
	} {
		code := "123456"
		if _, err := m.VerifyStep(s, code, 0); !errors.Is(err, totp.ErrInvalidSecret) {
			t.Errorf("%s: VerifyStep = %v, want ErrInvalidSecret", name, err)
		}
		if err := m.Verify(t.Context(), s, code, &memRecorder{}); !errors.Is(err, totp.ErrInvalidSecret) {
			t.Errorf("%s: Verify = %v, want ErrInvalidSecret", name, err)
		}
	}
}

// Twenty bytes fill 32 base32 characters exactly, so the last character has no
// unused bits and every respelling of it is a different key. A respelled
// secret never verifies the original key's code.
func TestHostile_TOTP_respelledSecretIsADifferentKey(t *testing.T) {
	m := newModule(t)
	secret := sharedSecret(t)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	last := strings.IndexByte(alphabet, secret[len(secret)-1])
	if last < 0 {
		t.Fatalf("last character %q not in the base32 alphabet", secret[len(secret)-1])
	}
	refused := 0
	for bit := 0; bit < 5; bit++ {
		alt := alphabet[last^(1<<bit)]
		spelled := secret[:len(secret)-1] + string(alt)
		// Twenty bytes use 160 bits in 32 characters, so the last character
		// carries no unused bits and every spelling is a different key. The
		// property that matters is that a different spelling never verifies
		// the original key's code.
		atStableStep(t, func(step uint64) string {
			if _, err := m.VerifyStep(spelled, codeAt(t, secret, step), 0); err == nil {
				return fmt.Sprintf("a respelled secret verified the original key's code (bit %d)", bit)
			}
			refused++
			return ""
		})
	}
	if refused == 0 {
		t.Fatal("nothing was checked")
	}
}

// Enroll writes a fresh secret and fresh recovery codes every time and the
// secret it writes is one Verify accepts.
func TestHostile_Enroll_materialIsFreshAndSelfConsistent(t *testing.T) {
	m := newModule(t, totp.Config{RecoveryCodeCount: 20})
	secrets, codes := map[string]bool{}, map[string]bool{}
	for i := 0; i < 100; i++ {
		enr, err := m.Enroll("user@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if secrets[enr.Secret] {
			t.Fatal("two enrolments produced one secret")
		}
		secrets[enr.Secret] = true
		if len(enr.RecoveryCodes) != 20 || len(enr.RecoveryHashes) != 20 {
			t.Fatalf("got %d codes and %d hashes, want 20 of each", len(enr.RecoveryCodes), len(enr.RecoveryHashes))
		}
		for j, c := range enr.RecoveryCodes {
			if codes[c] {
				t.Fatalf("recovery code %q issued twice", c)
			}
			codes[c] = true
			if len(c) != 17 || c[8] != '-' {
				t.Fatalf("recovery code %q is not XXXXXXXX-XXXXXXXX", c)
			}
			if h, err := m.HashRecoveryCode(c); err != nil || h != enr.RecoveryHashes[j] {
				t.Fatalf("hash %d does not match HashRecoveryCode", j)
			}
		}
	}
	enr, _ := m.Enroll("check@example.com")
	atStableStep(t, func(step uint64) string {
		if _, err := m.VerifyStep(enr.Secret, codeAt(t, enr.Secret, step), 0); err != nil {
			return fmt.Sprintf("a freshly enrolled secret does not verify: %v", err)
		}
		return ""
	})
}
