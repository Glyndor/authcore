package confusion

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// The JWT subject must be a UUID v7. Empty, Unicode look-alike digits and
// embedded NUL are refused; upper case is accepted and stored in lower case.
func TestMisuse_Confusion_jwtSubjectIsStrict(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	bad := []string{
		"", " ", "x", hostiletest.Subject + "\x00", hostiletest.Subject + "\n",
		"０" + hostiletest.Subject[1:], "0191b432-b5a7-4c4f-b2e6-7a3f1d2e0001", // v4 UUID
		"urn:uuid:" + hostiletest.Subject,
	}
	for _, s := range bad {
		var err error
		hostiletest.NoPanic(t, "CreateTokens", func() { _, err = j.CreateTokens(s, struct{}{}) })
		if !errors.Is(err, jwt.ErrInvalidSubject) {
			t.Errorf("subject %q: %v", s, err)
		}
	}
	pair, err := j.CreateTokens(strings.ToUpper(hostiletest.Subject), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil || c.Subject != hostiletest.Subject {
		t.Errorf("upper-case subject came back as %q, %v", c.Subject, err)
	}
}

// Hashing the access token where the refresh token belongs gives a different
// key, so a lookup for the wrong token kind finds nothing.
func TestMisuse_Confusion_refreshHashSeparatesTokens(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	pair, _ := j.CreateTokens(hostiletest.Subject, struct{}{})
	r, err := j.HashRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := j.HashRefreshToken(pair.AccessToken)
	if r == a || r == "" {
		t.Error("the access token and the refresh token hash alike")
	}
	if !j.VerifyRefreshTokenHash(pair.RefreshToken, r) {
		t.Fatal("control: the refresh token does not match its own hash")
	}
	if j.VerifyRefreshTokenHash(r, pair.RefreshToken) || j.VerifyRefreshTokenHash(pair.AccessToken, r) ||
		j.VerifyRefreshTokenHash(pair.RefreshToken, a) || j.VerifyRefreshTokenHash("", r) || j.VerifyRefreshTokenHash(pair.RefreshToken, "") {
		t.Error("a swapped, mismatched or empty argument matches a refresh token hash")
	}
	if _, err := j.HashRefreshToken(""); err != nil {
		t.Errorf("HashRefreshToken of the empty string errored: %v", err)
	}
	// A pair made by another installation's keys does not rotate here.
	foreign := hostiletest.NewEnv(t)
	fj, _ := jwt.New[struct{}](foreign.AC)
	fp, _ := fj.CreateTokens(hostiletest.Subject, struct{}{})
	if _, err := j.RotateTokens(fp.RefreshToken, struct{}{}); err == nil {
		t.Error("a refresh token from another key set rotates")
	}
}

// The API key module refuses its arguments in the wrong order and refuses to
// parse a hash or a refresh token as a key.
func TestMisuse_Confusion_apikeyArgumentsInTheWrongOrder(t *testing.T) {
	e := hostiletest.NewEnv(t)
	ak, _ := apikey.New(e.AC)
	g, err := ak.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !ak.Verify(g.Key, g.Hash) {
		t.Fatal("control: a generated key does not verify")
	}
	if ak.Verify(g.Hash, g.Key) {
		t.Error("key and hash swapped verify")
	}
	if ak.Verify(g.Key, g.ID) {
		t.Error("the public id verifies as the stored hash")
	}
	for _, s := range []string{g.Hash, g.ID, "", "ak_", "ak__", strings.ToUpper(g.Key), g.Key + "\n", " " + g.Key} {
		if _, err := ak.ParseID(s); !errors.Is(err, apikey.ErrInvalidKey) {
			t.Errorf("ParseID(%.20q): %v", s, err)
		}
	}
}

// TOTP calls with the secret and the code in the wrong order, an empty code or
// an empty secret are refusals, and recovery codes survive the way people type
// them.
func TestMisuse_Confusion_totpArgumentsAndRecoveryCodeTyping(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, _ := totp.New(e.AC)
	enr, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"secret and code swapped": func() error { _, err := m.VerifyStep("123456", enr.Secret, 0); return err },
		"empty code":              func() error { _, err := m.VerifyStep(enr.Secret, "", 0); return err },
		"empty secret":            func() error { _, err := m.VerifyStep("", "123456", 0); return err },
		"URI as the secret":       func() error { _, err := m.VerifyStep(enr.URI, "123456", 0); return err },
		"seven digits":            func() error { _, err := m.VerifyStep(enr.Secret, "1234567", 0); return err },
		"full-width digits":       func() error { _, err := m.VerifyStep(enr.Secret, "１２３４５６", 0); return err },
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	code := enr.RecoveryCodes[2]
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if i, ok := m.VerifyRecoveryCode(typed, enr.RecoveryHashes); !ok || i != 2 {
		t.Errorf("a recovery code typed with spaces and lower case: %d, %v", i, ok)
	}
	if _, ok := m.VerifyRecoveryCode(enr.Secret, enr.RecoveryHashes); ok {
		t.Error("the TOTP secret matched a recovery hash")
	}
}

// The password argument order and the Unicode forms of one password.
func TestMisuse_Confusion_passwordArgumentsAndUnicodeForms(t *testing.T) {
	e := hostiletest.NewEnv(t)
	pw, _ := password.New(e.AC)
	plain := "Correct-Horse-9-Battery-Staple"
	hash, err := pw.Hash(plain)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := pw.Verify(hash, plain); ok || !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("hash and plaintext swapped: %v %v", ok, err)
	}
	if ok, _ := pw.Verify("", hash); ok {
		t.Error("the empty password verifies against a real hash")
	}
	composed := "Café-Horse-9-Battery-Staple"
	decomposed := "Café-Horse-9-Battery-Staple"
	h, err := pw.Hash(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := pw.Verify(composed, h); err != nil || !ok {
		t.Errorf("the composed spelling does not verify the decomposed one: %v %v", ok, err)
	}
	for name, s := range map[string]string{
		"zero-width space": "Correct-Horse-9-Battery\u200b-Staple", "NUL": "Correct-Horse-9-Battery\x00-Staple",
		"right-to-left override": "Correct-Horse-9-\u202eBattery-Staple", "invalid UTF-8": "Correct-Horse-9-\xff-Battery-Staple",
		"no-break space": "Correct Horse-9-Battery-Staple",
	} {
		if _, err := pw.Hash(s); !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%s: hashed (%v)", name, err)
		}
	}
}

// Names and addresses in forms that read alike. Anything that is not the plain
// form is refused or normalised, never stored as a second identity.
func TestMisuse_Confusion_nameAndAddressLookAlikes(t *testing.T) {
	e := hostiletest.NewEnv(t)
	u, _ := username.New(e.AC)
	for _, s := range []string{"ADMIN", "Admin", " admin ", "ａdmin", "admin\u200b", "admın", "bob\x00", "ána"} {
		if got, err := u.ValidateAndNormalize(s); err == nil {
			t.Errorf("username %q accepted as %q", s, got)
		}
	}
	m, _ := email.New(e.AC)
	for _, s := range []string{"", "a@b@c.com", "Ana <a@example.com>", "a@example.com\x00", "a b@example.com", "a@[127.0.0.1]", "a@example.com."} {
		if got, err := m.ValidateAndNormalize(s); err == nil {
			t.Errorf("email %q accepted as %q", s, got)
		}
	}
	if got, err := m.ValidateAndNormalize(" Ana.Lopez@EXAMPLE.com "); err != nil || got != "ana.lopez@example.com" {
		t.Errorf("control: %q %v", got, err)
	}
}
