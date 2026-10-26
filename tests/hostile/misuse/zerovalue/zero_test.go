// Package zerovalue declares a variable and calls a method without ever
// calling New, or builds a module from a provider that is not a working one.
// The distracted developer's mistake is `var m jwt.JWT[T]` or a typed nil, and
// the library must answer with a clear error, never a panic and never an
// acceptance.
package zerovalue

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// op is one call on a module that was never built. want is the sentinel the
// module documents for that state.
type op struct {
	name string
	want error
	call func() error
}

func jwtOps(m *jwt.JWT[int]) []op {
	return []op{
		{"CreateTokens", jwt.ErrNotInitialised, func() error { _, err := m.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001", 1); return err }},
		{"VerifyAccessToken", jwt.ErrNotInitialised, func() error { _, err := m.VerifyAccessToken("a.b.c"); return err }},
		{"VerifyAccessTokenContext", jwt.ErrNotInitialised, func() error { _, err := m.VerifyAccessTokenContext(context.Background(), "a.b.c"); return err }},
		{"RotateTokens", jwt.ErrNotInitialised, func() error { _, err := m.RotateTokens("a.b.c", 1); return err }},
		{"RotateTokensContext", jwt.ErrNotInitialised, func() error { _, err := m.RotateTokensContext(context.Background(), "a.b.c", 1); return err }},
		{"HashRefreshToken", jwt.ErrNotInitialised, func() error { _, err := m.HashRefreshToken("a"); return err }},
	}
}

func totpOps(m *totp.TOTP) []op {
	ctx := context.Background()
	return []op{
		{"Enroll", totp.ErrNotInitialised, func() error { _, err := m.Enroll("ana"); return err }},
		{"VerifyStep", totp.ErrNotInitialised, func() error { _, err := m.VerifyStep("JBSWY3DPEHPK3PXP", "123456", 0); return err }},
		{"Verify", totp.ErrNotInitialised, func() error { return m.Verify(ctx, "JBSWY3DPEHPK3PXP", "123456", nil) }},
		{"HashRecoveryCode", totp.ErrNotInitialised, func() error { _, err := m.HashRecoveryCode("abcd-efgh"); return err }},
	}
}

func apikeyOps(m *apikey.APIKey) []op {
	return []op{
		{"Generate", apikey.ErrNotInitialised, func() error { _, err := m.Generate(); return err }},
		{"Hash", apikey.ErrNotInitialised, func() error { _, err := m.Hash("ak_x_y"); return err }},
	}
}

func credentialOps(m *credential.Credential) []op {
	return []op{
		{"Issue", credential.ErrNotInitialised, func() error { _, err := m.Issue("reset", "user-1"); return err }},
		{"Verify", credential.ErrNotInitialised, func() error { return m.Verify("reset", "user-1", "tok", "", time.Now()) }},
	}
}

func fieldOps(m *field.Field) []op {
	return []op{
		{"Encrypt", field.ErrNotInitialised, func() error { _, err := m.Encrypt("a"); return err }},
		{"Decrypt", field.ErrNotInitialised, func() error { _, err := m.Decrypt("a"); return err }},
		{"BlindIndex", field.ErrNotInitialised, func() error { _, err := m.BlindIndex("a"); return err }},
	}
}

func run(t *testing.T, label string, ops []op) {
	t.Helper()
	for _, o := range ops {
		t.Run(label+"/"+o.name, func(t *testing.T) {
			var got error
			hostiletest.NoPanic(t, o.name, func() { got = o.call() })
			if !errors.Is(got, o.want) {
				t.Fatalf("got %v, want %v", got, o.want)
			}
		})
	}
}

// A module that was declared and never built refuses every operation that
// would otherwise run with an empty key.
func TestMisuse_ZeroValue_unbuiltModulesRefuseWork(t *testing.T) {
	var j jwt.JWT[int]
	var tp totp.TOTP
	var ak apikey.APIKey
	var cr credential.Credential
	var fd field.Field
	run(t, "jwt", jwtOps(&j))
	run(t, "totp", totpOps(&tp))
	run(t, "apikey", apikeyOps(&ak))
	run(t, "credential", credentialOps(&cr))
	run(t, "field", fieldOps(&fd))
}

// A nil pointer to a module is the same mistake with a different spelling. The
// modules that document nil safety keep that promise.
func TestMisuse_ZeroValue_nilModulesRefuseWork(t *testing.T) {
	var j *jwt.JWT[int]
	var tp *totp.TOTP
	run(t, "jwt", jwtOps(j))
	run(t, "totp", totpOps(tp))
}

// A zero module has no pepper. Anything it hashed would be keyed by nothing,
// so it must not accept a key, a recovery code or a stored hash as valid.
func TestMisuse_ZeroValue_unbuiltModulesNeverAccept(t *testing.T) {
	var ak apikey.APIKey
	var tp totp.TOTP
	var zj jwt.JWT[int]
	var nj *jwt.JWT[int]
	for _, j := range []*jwt.JWT[int]{&zj, nj} {
		for _, stored := range []string{"", "00", strings.Repeat("0", 64)} {
			if j.VerifyRefreshTokenHash("", stored) || j.VerifyRefreshTokenHash("a.b.c", stored) {
				t.Errorf("an unbuilt JWT module verified a refresh hash against %q", stored)
			}
		}
	}
	for _, key := range []string{"", "ak_x_y", "ak_aaaaaaaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		for _, stored := range []string{"", key, "00"} {
			if ak.Verify(key, stored) {
				t.Errorf("zero APIKey accepted key %q against stored %q", key, stored)
			}
		}
	}
	if _, err := ak.ParseID("ak_aaaaaaaaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("zero APIKey ParseID: got %v", err)
	}
	if i, ok := tp.VerifyRecoveryCode("abcd-efgh", []string{"", "00"}); ok || i != 0 {
		t.Errorf("zero TOTP accepted a recovery code (index %d)", i)
	}
}

// A zero Password has no policy and no work factor. It must not panic out of
// Verify and must not accept a wrong password for a real hash.
func TestMisuse_ZeroValue_unbuiltPasswordDoesNotAcceptWrongPassword(t *testing.T) {
	e := hostiletest.NewEnv(t)
	good, err := password.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := good.Hash("Correct-Horse-9-Battery-Staple")
	if err != nil {
		t.Fatal(err)
	}
	var zero password.Password
	var ok bool
	hostiletest.NoPanic(t, "zero Password.Verify", func() { ok, _ = zero.Verify("not-the-password", hash) })
	if ok {
		t.Fatal("zero Password accepted a wrong password")
	}
	if got := zero.Name(); got != "password" {
		t.Errorf("Name on a zero value = %q", got)
	}
}

// A zero Username has no length bounds. Failing closed is the only safe answer
// for a name policy: nothing is valid until the module is built.
func TestMisuse_ZeroValue_unbuiltUsernameFailsClosed(t *testing.T) {
	var u username.Username
	for _, name := range []string{"bob", "admin", "a-valid-name", ""} {
		var err error
		hostiletest.NoPanic(t, "zero Username", func() { _, err = u.ValidateAndNormalize(name) })
		if !errors.Is(err, username.ErrInvalidUsername) {
			t.Errorf("zero Username on %q: got %v, want ErrInvalidUsername", name, err)
		}
	}
}

// Close on an Email that was never built, or closed twice, is harmless.
func TestMisuse_ZeroValue_emailCloseIsHarmless(t *testing.T) {
	var zero email.Email
	var nilEmail *email.Email
	hostiletest.NoPanic(t, "Close", func() {
		zero.Close()
		zero.Close()
		nilEmail.Close()
	})
}
