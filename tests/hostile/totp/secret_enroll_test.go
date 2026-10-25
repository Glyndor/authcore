package totp_test

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
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

// A recovery code is found by value in the stored list wherever it sits, in
// any of the spellings a user types, and nothing else is found: not a near
// miss, not another script's lookalike, not an empty string.
func TestHostile_Recovery_lookupIsExactOverTheNormalisedForm(t *testing.T) {
	m := newModule(t, totp.Config{RecoveryCodeCount: 10})
	enr, err := m.Enroll("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for i, code := range enr.RecoveryCodes {
		idx, ok := m.VerifyRecoveryCode(code, enr.RecoveryHashes)
		if !ok || idx != i {
			t.Fatalf("code %d found at %d, %v", i, idx, ok)
		}
	}

	target := enr.RecoveryCodes[3]
	plain := strings.ReplaceAll(target, "-", "")
	for name, spelled := range map[string]string{
		"lower case":      strings.ToLower(target),
		"no hyphen":       plain,
		"spaces":          plain[:4] + " " + plain[4:8] + " " + plain[8:12] + " " + plain[12:],
		"padded":          "  " + target + "  ",
		"hyphen as space": strings.Replace(target, "-", " ", 1),
	} {
		if idx, ok := m.VerifyRecoveryCode(spelled, enr.RecoveryHashes); !ok || idx != 3 {
			t.Errorf("%s: %q found at %d, %v; want index 3", name, spelled, idx, ok)
		}
	}

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	for name, miss := range map[string]string{
		"empty":               "",
		"only hyphens":        "----",
		"first character off": flip(target, 0),
		"last character off":  flip(target, len(target)-1),
		"truncated":           target[:len(target)-1],
		"extended":            target + "A",
		"doubled":             target + target,
		"tab separated":       strings.Replace(target, "-", "\t", 1),
		"newline inside":      target[:4] + "\n" + target[4:],
		"NUL inside":          target[:4] + "\x00" + target[4:],
		"zero width space":    target[:4] + "\u200b" + target[4:],
		"fullwidth hyphen":    strings.Replace(target, "-", "\uff0d", 1),
		"cyrillic lookalike":  "\u0410" + target[1:],
		"digit zero for O":    strings.Replace(target, "O", "0", 1) + "x",
		"one MiB":             strings.Repeat("A", 1<<20),
		"another account's":   mustEnrollCode(t, m),
	} {
		if idx, ok := m.VerifyRecoveryCode(miss, enr.RecoveryHashes); ok {
			t.Errorf("%s: %q was found at %d", name, miss, idx)
		}
	}

	if idx, ok := m.VerifyRecoveryCode(target, nil); ok {
		t.Errorf("found in a nil list at %d", idx)
	}
	if idx, ok := m.VerifyRecoveryCode(target, []string{"", "x", strings.ToUpper(enr.RecoveryHashes[3])}); ok {
		t.Errorf("matched a malformed or re-cased stored hash at %d", idx)
	}
}

func mustEnrollCode(t testing.TB, m *totp.TOTP) string {
	t.Helper()
	enr, err := m.Enroll("other@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return enr.RecoveryCodes[0]
}

// Recovery codes are single-use because the application removes the entry it
// is told about. The module's part is to be stateless and exact: the same list
// and code always give the same index, even from many goroutines, and after the
// entry is removed the code is gone.
func TestHostile_Recovery_codeIsGoneOnceTheEntryIsRemoved(t *testing.T) {
	m := newModule(t)
	enr, _ := m.Enroll("user@example.com")
	code := enr.RecoveryCodes[5]

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if idx, ok := m.VerifyRecoveryCode(code, enr.RecoveryHashes); !ok || idx != 5 {
				t.Errorf("concurrent lookup = %d, %v; want 5, true", idx, ok)
			}
		}()
	}
	wg.Wait()

	remaining := append(append([]string{}, enr.RecoveryHashes[:5]...), enr.RecoveryHashes[6:]...)
	if idx, ok := m.VerifyRecoveryCode(code, remaining); ok {
		t.Fatalf("a consumed code was found again at %d", idx)
	}
	if idx, ok := m.VerifyRecoveryCode(enr.RecoveryCodes[6], remaining); !ok || idx != 5 {
		t.Fatalf("the code after the removed one = %d, %v; want index 5", idx, ok)
	}
}

// The recovery hash is keyed with the deployment's secret, so a list of hashes
// taken from one deployment is not a list of codes anywhere else.
func TestHostile_Recovery_hashesAreBoundToTheDeployment(t *testing.T) {
	a, b := newModule(t), newModule(t)
	enr, _ := a.Enroll("user@example.com")
	if _, ok := b.VerifyRecoveryCode(enr.RecoveryCodes[0], enr.RecoveryHashes); ok {
		t.Fatal("a recovery hash from another deployment verified")
	}
	hb, _ := b.HashRecoveryCode(enr.RecoveryCodes[0])
	if hb == enr.RecoveryHashes[0] {
		t.Fatal("two deployments hashed one code to the same value")
	}
}

// The provisioning URI is built from the account name and the issuer, both of
// which an attacker may choose (a display name, an email local part). Whatever
// they contain, the URI that comes out has one secret, the fixed algorithm,
// digits and period, and the label and issuer it was given.
func TestHostile_Enroll_provisioningURIResistsInjection(t *testing.T) {
	hostile := map[string]string{
		"extra secret param":  "alice&secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"question mark":       "alice?secret=AAAA",
		"fragment":            "alice#secret=AAAA",
		"override algorithm":  "alice@example.com&algorithm=SHA512&digits=8&period=60",
		"semicolon":           "alice;secret=AAAA",
		"path traversal":      "../../evil",
		"colon":               "evil:alice",
		"double colon":        "a:b:c",
		"percent sequences":   "%00%0d%0a%26secret%3dAAAA",
		"literal percent":     "100%",
		"newline":             "alice\nsecret=AAAA",
		"carriage return":     "alice\r\nHost: evil",
		"NUL":                 "alice\x00",
		"space":               "alice smith",
		"plus":                "alice+tag@example.com",
		"slash":               "a/b",
		"backslash":           `a\b`,
		"quotes":              `"alice"'`,
		"angle brackets":      "<script>alert(1)</script>",
		"unicode":             "Se\u00f1or L\u00f3pez \u65e5\u672c",
		"bidi override":       "alice\u202egnp.exe",
		"empty":               "",
		"very long":           strings.Repeat("a", 4096),
		"invalid UTF-8":       "alice\xff\xfe",
		"scheme confusion":    "javascript:alert(1)",
		"authority confusion": "//evil.example/x",
	}
	for name, account := range hostile {
		for _, issuer := range []string{"", "Acme", "Evil&secret=AAAA", "Acme:Co", "A/B?c#d", "\u00dcber Corp"} {
			m := newModule(t, totp.Config{Issuer: issuer})
			enr, err := m.Enroll(account)
			if err != nil {
				t.Fatalf("%s/%q: Enroll: %v", name, issuer, err)
			}
			checkURI(t, fmt.Sprintf("%s/%q", name, issuer), enr, issuer)
		}
	}
}

// hasRawUnsafeByte reports the first byte of uri that must have been escaped.
func hasRawUnsafeByte(uri string) (int, bool) {
	for i := 0; i < len(uri); i++ {
		if c := uri[i]; c < 0x20 || c == 0x7f || c == ' ' || c == '"' || c == '<' || c == '>' || c >= 0x80 {
			return i, true
		}
	}
	return 0, false
}

func checkURI(t *testing.T, label string, enr *totp.Enrollment, issuer string) {
	t.Helper()
	if i, bad := hasRawUnsafeByte(enr.URI); bad {
		t.Errorf("%s: the URI holds the raw byte %#x at %d: %.80q", label, enr.URI[i], i, enr.URI)
		return
	}
	u, err := url.Parse(enr.URI)
	if err != nil {
		t.Errorf("%s: the URI does not parse: %v", label, err)
		return
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" || u.User != nil {
		t.Errorf("%s: scheme=%q host=%q fragment=%q user=%v", label, u.Scheme, u.Host, u.Fragment, u.User)
	}
	q := u.Query()
	for key, want := range map[string]string{"secret": enr.Secret, "algorithm": "SHA1", "digits": "6", "period": "30"} {
		if vals := q[key]; len(vals) != 1 || vals[0] != want {
			t.Errorf("%s: %s = %q, want exactly [%q]", label, key, vals, want)
		}
	}
	// The first colon of the label separates issuer from account, so a colon
	// inside either must have been escaped: one raw colon with an issuer, none
	// without.
	wantColons := 0
	if issuer != "" {
		wantColons = 1
	}
	if got := strings.Count(u.EscapedPath(), ":"); got != wantColons {
		t.Errorf("%s: the label holds %d raw colons, want %d: %s", label, got, wantColons, u.EscapedPath())
	}
	wantKeys := 4
	if issuer != "" {
		wantKeys = 5
		if vals := q["issuer"]; len(vals) != 1 || vals[0] != issuer {
			t.Errorf("%s: issuer = %q, want [%q]", label, vals, issuer)
		}
	}
	if len(q) != wantKeys {
		t.Errorf("%s: the URI carries %d query keys, want %d: %v", label, len(q), wantKeys, q)
	}
}
