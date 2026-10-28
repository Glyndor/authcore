// Package configzero builds every module from an empty or partial Config and
// from values that look like "off": a zero TTL, a nil pointer, a negative
// leeway, Argon2 parameters of one. The safe default must apply, or the build
// must fail. What must never happen is a zero that quietly disables a control.
package configzero

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// An empty authcore.Config builds with the documented defaults, writes its keys
// under the default directory and does not leave them readable by others.
func TestMisuse_ConfigZero_authcoreEmptyConfigIsSafe(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ac, err := authcore.New(authcore.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if ac.Config().Timezone != time.UTC {
		t.Errorf("zero Timezone resolved to %v, want UTC", ac.Config().Timezone)
	}
	if ac.Config().KeysDir != ".authcore" {
		t.Errorf("zero KeysDir resolved to %q", ac.Config().KeysDir)
	}
	if got := len(ac.Keys().RefreshSecret()); got != 32 {
		t.Errorf("refresh secret is %d bytes", got)
	}
	keysDir := filepath.Join(dir, ".authcore")
	// The public key may be world-readable; the directory and the two secrets
	// may not.
	for _, name := range []string{"", "ed25519_private.pem", "refresh_secret.key"} {
		path := filepath.Join(keysDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 { // Windows reports a synthetic 0666/0777 mode, not the ACL
			t.Errorf("%s is %v, readable by group or others", path, info.Mode().Perm())
		}
	}
}

// A Config with a negative or absurd duration is refused, never clamped to
// something that disables expiry.
func TestMisuse_ConfigZero_jwtRefusesDurationsThatDisableAControl(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cases := map[string]jwt.Config{
		"negative access TTL":         {AccessTokenTTL: -time.Minute},
		"sub-second access TTL":       {AccessTokenTTL: time.Millisecond},
		"access TTL beyond a day":     {AccessTokenTTL: 48 * time.Hour},
		"negative refresh TTL":        {RefreshTokenTTL: -time.Hour},
		"refresh below the default":   {RefreshTokenTTL: 10 * time.Minute},
		"refresh equals access":       {AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour},
		"refresh beyond a year":       {RefreshTokenTTL: 366 * 24 * time.Hour},
		"negative leeway":             {ClockSkewLeeway: -time.Second},
		"leeway beyond five minutes":  {ClockSkewLeeway: time.Hour},
		"blank audience entry":        {Audience: []string{" "}},
		"empty audience entry":        {Audience: []string{"ok", ""}},
		"typed nil denylist":          {Denylist: (*nilDenylist)(nil)},
		"previous key of wrong size":  {PreviousPublicKeys: shortKey()},
		"previous key all zero bytes": {PreviousPublicKeys: zeroKey()},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "jwt.New", func() { _, err = jwt.New[struct{}](e.AC, cfg) })
			if !errors.Is(err, jwt.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// An empty jwt.Config is the default Config: 15 minute access tokens, one day
// refresh tokens, the default issuer and audience. A zero is not "no limit".
func TestMisuse_ConfigZero_jwtEmptyConfigAppliesTheDefaults(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := jwt.New[struct{}](e.AC, jwt.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := m.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(pair.AccessTokenExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
		t.Errorf("access token lives %s, want about 15m", d)
	}
	if d := time.Until(pair.RefreshTokenExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("refresh token lives %s, want about 24h", d)
	}
	claims, err := m.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	def := jwt.DefaultConfig()
	if claims.Issuer != def.Issuer || len(claims.Audience) != 1 || claims.Audience[0] != def.Audience[0] {
		t.Errorf("issuer/audience %q %v are not the defaults", claims.Issuer, claims.Audience)
	}
	// The defaults must still bind: a module configured for another issuer
	// issues tokens the default module refuses.
	other, err := jwt.New[struct{}](e.AC, jwt.Config{Issuer: "someone-else"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(foreign.AccessToken); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Errorf("a token for another issuer against a module with an empty Config: %v; want ErrTokenInvalid", err)
	}
}

var phcParams = regexp.MustCompile(`\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$`)

func phcOf(t *testing.T, hash string) (m, it, p int) {
	t.Helper()
	g := phcParams.FindStringSubmatch(hash)
	if g == nil {
		t.Fatalf("not a PHC argon2id string: %q", hash)
	}
	m, _ = strconv.Atoi(g[1])
	it, _ = strconv.Atoi(g[2])
	p, _ = strconv.Atoi(g[3])
	return m, it, p
}

// Zeros in the Argon2 parameters take the default; they never reach the hash
// as a cost of nothing.
func TestMisuse_ConfigZero_passwordZeroCostParametersTakeTheDefault(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, cfg := range map[string]password.Config{
		"empty":           {},
		"only iterations": {Iterations: 4},
		"only memory":     {Memory: 32 * 1024},
		"only length":     {MinLength: 14},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := password.New(e.AC, cfg)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := m.Hash("Correct-Horse-9-Battery-Staple")
			if err != nil {
				t.Fatal(err)
			}
			mem, iter, par := phcOf(t, hash)
			def := password.DefaultConfig()
			if mem < 8*1024 || iter < 1 || par < 1 {
				t.Errorf("hash cost m=%d t=%d p=%d is below any usable floor", mem, iter, par)
			}
			if cfg.Memory == 0 && uint32(mem) != def.Memory { // #nosec G115 -- the value was parsed from a short decimal
				t.Errorf("memory %d, want the default %d", mem, def.Memory)
			}
			if cfg.Iterations == 0 && uint32(iter) != def.Iterations { // #nosec G115 -- as above
				t.Errorf("iterations %d, want the default %d", iter, def.Iterations)
			}
		})
	}
}

// Values that would weaken the hash or the policy below the floors fail New.
func TestMisuse_ConfigZero_passwordRefusesValuesBelowTheFloors(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, cfg := range map[string]password.Config{
		"memory of one KiB":      {Memory: 1},
		"min length of zero-ish": {MinLength: 1},
		"min length of four":     {MinLength: 4},
		"negative min length":    {MinLength: -3},
		"negative max length":    {MaxLength: -1},
		"max below min":          {MinLength: 20, MaxLength: 12},
		"unbounded max length":   {MaxLength: 1 << 30},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, "password.New", func() { _, err = password.New(e.AC, cfg) })
			if !errors.Is(err, password.ErrInvalidConfig) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// With nothing set, the policy is the strict one: 12 to 64 runes and all four
// classes. A zero length or a nil flag does not switch a rule off.
func TestMisuse_ConfigZero_passwordEmptyConfigKeepsTheStrictPolicy(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := password.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	for name, weak := range map[string]string{
		"empty":      "",
		"eleven":     "Abcdefgh1!x",
		"no upper":   "abcdefghijk1!xyz",
		"no lower":   "ABCDEFGHIJK1!XYZ",
		"no digit":   "Abcdefghijkl!xyz",
		"no symbol":  "Abcdefghijkl1xyz",
		"too long":   strings.Repeat("Ab1!", 17),
		"huge input": strings.Repeat("Ab1!", 1<<16),
	} {
		if err := m.ValidatePolicy(weak); !errors.Is(err, password.ErrWeakPassword) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if err := m.ValidatePolicy("Abcdefghijk1!xyz"); err != nil {
		t.Errorf("control: a compliant password is refused: %v", err)
	}
}
