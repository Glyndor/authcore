package configcopy

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// The password policy flags are pointers. Flipping one through the caller's
// pointer after New must not relax what the module accepts.
func TestMisuse_ConfigCopy_passwordPolicyPointersAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := password.Config{RequireSymbol: password.Bool(true), RequireDigit: password.Bool(true)}
	m, err := password.New(e.AC, cfg)
	if err != nil {
		t.Fatal(err)
	}
	*cfg.RequireSymbol = false
	*cfg.RequireDigit = false
	if err := m.ValidatePolicy("Abcdefghijk1!xyz"); err != nil {
		t.Fatalf("control: a password that meets the policy is refused: %v", err)
	}
	for _, weak := range []string{"Abcdefghijklmnop1", "Abcdefghijklmnop!", "Abcdefghijklmnopq"} {
		if err := m.ValidatePolicy(weak); !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%q accepted after the caller cleared the flags: %v", weak, err)
		}
	}
}

// SkewSteps is a pointer. Raising it through the caller's pointer after New
// must not widen the window of codes the module accepts.
func TestMisuse_ConfigCopy_totpSkewPointerIsSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := totp.Config{SkewSteps: totp.Int(1)}
	m, err := totp.New(e.AC, cfg)
	if err != nil {
		t.Fatal(err)
	}
	*cfg.SkewSteps = 10
	enr, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := m.VerifyStep(enr.Secret, hostiletest.TOTPCode(t, enr.Secret, now), 0); err != nil {
		t.Fatalf("control: the current code is refused: %v", err)
	}
	stale := hostiletest.TOTPCode(t, enr.Secret, now.Add(-95*time.Second))
	if _, err := m.VerifyStep(enr.Secret, stale, 0); !errors.Is(err, totp.ErrInvalidCode) {
		t.Fatalf("a code from three steps ago is accepted after the caller raised SkewSteps: %v", err)
	}
}

// The reserved-name slices are the caller's. Rewriting them after New must not
// reserve a different set of names.
func TestMisuse_ConfigCopy_usernameReservedSlicesAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	control, err := username.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"admin", "root"} {
		if _, err := control.ValidateAndNormalize(n); err == nil {
			t.Fatalf("control: %q is not reserved by default, so this test proves nothing", n)
		}
	}
	cfg := username.Config{ExtraReservedNames: []string{"zzfoo"}, AllowReservedNames: []string{"admin"}}
	m, err := username.NewWithConfig(e.AC, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ExtraReservedNames[0] = "zzbar"
	cfg.AllowReservedNames[0] = "root"
	for name, wantOK := range map[string]bool{"zzfoo": false, "zzbar": true, "admin": true, "root": false} {
		_, err := m.ValidateAndNormalize(name)
		if (err == nil) != wantOK {
			t.Errorf("%q: accepted=%v, want %v (err %v)", name, err == nil, wantOK, err)
		}
	}
}

func scopeOf(t *testing.T, c *oauth.Client) string {
	t.Helper()
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("scope")
}

// Scopes and a preset's default scopes are slices the caller keeps. The scope
// the client asks the provider for is fixed when the client is built.
func TestMisuse_ConfigCopy_oauthScopeSlicesAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	base := oauth.Config{ClientID: "client", ClientSecret: "s", RedirectURL: "https://app.example.com/cb"}

	explicit := base
	explicit.Provider = oauth.Google()
	explicit.Scopes = []string{"openid", "email"}
	c1, err := oauth.New(e.AC, explicit)
	if err != nil {
		t.Fatal(err)
	}
	explicit.Scopes[1] = "https://www.googleapis.com/auth/drive"
	if got := scopeOf(t, c1); got != "openid email" {
		t.Errorf("explicit scopes changed after New: %q", got)
	}

	fallback := base
	fallback.Provider = oauth.Google()
	fallback.Provider.DefaultScopes = []string{"openid", "email"}
	c2, err := oauth.New(e.AC, fallback)
	if err != nil {
		t.Fatal(err)
	}
	fallback.Provider.DefaultScopes[0] = "https://www.googleapis.com/auth/drive"
	if got := scopeOf(t, c2); !strings.HasPrefix(got, "openid") {
		t.Errorf("default scopes changed after New: %q", got)
	}
}

// Configs made of values are snapshotted by assignment. The test pins that for
// every module that has one, so a later change to a pointer or a map shows up.
func TestMisuse_ConfigCopy_valueConfigsAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)

	akCfg := apikey.Config{Prefix: "mykey"}
	ak, err := apikey.New(e.AC, akCfg)
	if err != nil {
		t.Fatal(err)
	}
	akCfg.Prefix = "other"
	if g, err := ak.Generate(); err != nil || !strings.HasPrefix(g.Key, "mykey_") {
		t.Errorf("apikey prefix changed after New: %v %v", g, err)
	}

	crCfg := credential.Config{TTL: time.Minute}
	cr, err := credential.New(e.AC, crCfg)
	if err != nil {
		t.Fatal(err)
	}
	crCfg.TTL = 1000 * time.Hour
	iss, err := cr.Issue("reset", hostiletest.Subject)
	if err != nil {
		t.Fatal(err)
	}
	err = cr.Verify("reset", hostiletest.Subject, iss.Token, iss.Hash, time.Now().Add(-2*time.Minute))
	if !errors.Is(err, credential.ErrExpired) {
		t.Errorf("credential TTL changed after New: %v", err)
	}

	fdCfg := field.Config{Context: "users.email"}
	fd, err := field.New(e.AC, fdCfg)
	if err != nil {
		t.Fatal(err)
	}
	fdCfg.Context = "users.phone"
	ct, err := fd.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	same, _ := field.New(e.AC, field.Config{Context: "users.email"})
	other, _ := field.New(e.AC, field.Config{Context: "users.phone"})
	if _, err := same.Decrypt(ct); err != nil {
		t.Errorf("field context changed after New: %v", err)
	}
	if _, err := other.Decrypt(ct); err == nil {
		t.Error("a ciphertext decrypts under the context the caller wrote after New")
	}

	emCfg := email.Config{RejectPlusAddressing: true}
	em, err := email.NewWithConfig(e.AC, emCfg)
	if err != nil {
		t.Fatal(err)
	}
	emCfg.RejectPlusAddressing = false
	if _, err := em.ValidateAndNormalize("ana+tag@example.com"); err == nil {
		t.Error("email policy relaxed after New")
	}
}
