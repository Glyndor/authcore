package configzero

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// settle waits out the last second of a 30 s TOTP step, so a code computed and
// verified a few microseconds apart cannot straddle a step boundary.
func settle() {
	if s := time.Now().Unix() % 30; s >= 28 {
		time.Sleep(time.Duration(31-s) * time.Second)
	}
}

// SkewSteps nil is the default window of one step either side. Int(0) is a
// strict window, which is tighter, not off. Negative and huge values fail.
func TestMisuse_ConfigZero_totpSkewNilIsTheDefaultAndNeverWiderThanDeclared(t *testing.T) {
	e := hostiletest.NewEnv(t)
	settle()
	now := time.Now()
	for name, tc := range map[string]struct {
		cfg    []totp.Config
		oneAgo bool // is a code from the previous step accepted
	}{
		"no config":      {nil, true},
		"empty config":   {[]totp.Config{{}}, true},
		"nil SkewSteps":  {[]totp.Config{{Issuer: "x"}}, true},
		"explicit zero":  {[]totp.Config{{SkewSteps: totp.Int(0)}}, false},
		"explicit one":   {[]totp.Config{{SkewSteps: totp.Int(1)}}, true},
		"default config": {[]totp.Config{totp.DefaultConfig()}, true},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := totp.New(e.AC, tc.cfg...)
			if err != nil {
				t.Fatal(err)
			}
			enr, err := m.Enroll("ana@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.VerifyStep(enr.Secret, hostiletest.TOTPCode(t, enr.Secret, now), 0); err != nil {
				t.Fatalf("the current code is refused: %v", err)
			}
			_, err = m.VerifyStep(enr.Secret, hostiletest.TOTPCode(t, enr.Secret, now.Add(-30*time.Second)), 0)
			if (err == nil) != tc.oneAgo {
				t.Errorf("code from the previous step: accepted=%v, want %v", err == nil, tc.oneAgo)
			}
			if _, err := m.VerifyStep(enr.Secret, hostiletest.TOTPCode(t, enr.Secret, now.Add(-120*time.Second)), 0); err == nil {
				t.Error("a code from four steps ago is accepted")
			}
			if len(enr.RecoveryCodes) != 10 {
				t.Errorf("%d recovery codes, want the default 10", len(enr.RecoveryCodes))
			}
		})
	}
	for name, cfg := range map[string]totp.Config{
		"negative skew":         {SkewSteps: totp.Int(-1)},
		"skew beyond ten steps": {SkewSteps: totp.Int(11)},
		"negative recovery":     {RecoveryCodeCount: -1},
		"recovery beyond fifty": {RecoveryCodeCount: 51},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "totp.New", func() { _, err = totp.New(e.AC, cfg) })
			if !errors.Is(err, totp.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// A zero credential TTL is refused or defaulted; either way no token outlives
// the one day ceiling, and a negative TTL never builds.
func TestMisuse_ConfigZero_credentialZeroTTLNeverMeansForever(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, cfgs := range map[string][]credential.Config{
		"no config":      nil,
		"empty config":   {{}},
		"default":        {credential.DefaultConfig()},
		"one day":        {{TTL: 24 * time.Hour}},
		"one nanosecond": {{TTL: time.Nanosecond}},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := credential.New(e.AC, cfgs...)
			if err != nil {
				if !errors.Is(err, credential.ErrInvalidConfig) {
					t.Fatalf("got %v, want ErrInvalidConfig", err)
				}
				return
			}
			iss, err := m.Issue("reset", hostiletest.Subject)
			if err != nil {
				t.Fatal(err)
			}
			stale := time.Now().Add(-25 * time.Hour)
			if err := m.Verify("reset", hostiletest.Subject, iss.Token, iss.Hash, stale); !errors.Is(err, credential.ErrExpired) {
				t.Errorf("a token issued 25 hours ago verifies: %v", err)
			}
		})
	}
	for name, cfg := range map[string]credential.Config{
		"negative TTL": {TTL: -time.Hour},
		"beyond a day": {TTL: 25 * time.Hour},
	} {
		if _, err := credential.New(e.AC, cfg); !errors.Is(err, credential.ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
}

// An empty field context would put every column in one key space, so New
// refuses it. The zero Config and DefaultConfig both carry the empty context.
func TestMisuse_ConfigZero_fieldRefusesAnEmptyContext(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, cfgs := range map[string][]field.Config{
		"no config":      nil,
		"zero config":    {{}},
		"default config": {field.DefaultConfig()},
	} {
		var err error
		hostiletest.NoPanic(t, name, func() { _, err = field.New(e.AC, cfgs...) })
		if !errors.Is(err, field.ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
}

// The prefix is part of the key a user sees. An empty one takes the default;
// one that would break the key grammar is refused rather than rewritten.
func TestMisuse_ConfigZero_apikeyPrefixDefaultsOrFails(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := apikey.New(e.AC, apikey.Config{})
	if err != nil {
		t.Fatal(err)
	}
	g, err := m.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.Key, "ak_") {
		t.Errorf("default prefix missing from %q", g.Key)
	}
	for name, prefix := range map[string]string{
		"underscore": "my_key", "uppercase": "MyKey", "too long": strings.Repeat("a", 17),
		"space": "my key", "unicode": "clé",
	} {
		if _, err := apikey.New(e.AC, apikey.Config{Prefix: prefix}); !errors.Is(err, apikey.ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
}

// A username Config with zeros keeps the built-in bounds and the reserved
// list. Bounds that would admit everything fail.
func TestMisuse_ConfigZero_usernameZerosKeepTheBoundsAndTheReservedList(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, cfg := range map[string]username.Config{
		"empty":         {},
		"only extra":    {ExtraReservedNames: []string{"zzname", "", "  "}},
		"only allow":    {AllowReservedNames: []string{""}},
		"default":       username.DefaultConfig(),
		"min only zero": {MaxLength: 32},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := username.NewWithConfig(e.AC, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{"", "ab", strings.Repeat("a", 33), "admin", "root"} {
				if _, err := m.ValidateAndNormalize(bad); !errors.Is(err, username.ErrInvalidUsername) {
					t.Errorf("%q accepted (%v)", bad, err)
				}
			}
			if got, err := m.ValidateAndNormalize("  Ana_99 "); err != nil || got != "ana_99" {
				t.Errorf("control: got %q, %v", got, err)
			}
		})
	}
	for name, cfg := range map[string]username.Config{
		"negative min":  {MinLength: -1},
		"max below min": {MinLength: 10, MaxLength: 5},
		"unbounded max": {MaxLength: 1 << 20},
	} {
		if _, err := username.NewWithConfig(e.AC, cfg); !errors.Is(err, username.ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
}

// The OAuth client needs an HTTPS redirect and refuses private-network
// endpoints by default. A Config with the zero AllowPrivateNetwork is the
// strict one, and the two ways of giving a secret cannot be combined.
func TestMisuse_ConfigZero_oauthZeroValuesAreTheStrictOnes(t *testing.T) {
	e := hostiletest.NewEnv(t)
	good := oauth.Config{ClientID: "c", ClientSecret: "s", RedirectURL: "https://app.example.com/cb", Provider: oauth.Google()}
	if _, err := oauth.New(e.AC, good); err != nil {
		t.Fatalf("control: %v", err)
	}
	mutate := map[string]func(c *oauth.Config){
		"plain http redirect": func(c *oauth.Config) { c.RedirectURL = "http://app.example.com/cb" },
		"blank client id":     func(c *oauth.Config) { c.ClientID = "  " },
		"empty redirect":      func(c *oauth.Config) { c.RedirectURL = "" },
		"metadata token URL":  func(c *oauth.Config) { c.Provider.TokenURL = "https://169.254.169.254/token" },
		"private auth URL":    func(c *oauth.Config) { c.Provider.AuthURL = "https://10.0.0.5/auth" },
		"both secret forms": func(c *oauth.Config) {
			c.ClientSecretFunc = func(_ context.Context) (string, error) { return "x", nil }
		},
		"no endpoints": func(c *oauth.Config) { c.Provider = oauth.Provider{} },
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			cfg := good
			fn(&cfg)
			var err error
			hostiletest.NoPanic(t, "oauth.New", func() { _, err = oauth.New(e.AC, cfg) })
			if !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}
