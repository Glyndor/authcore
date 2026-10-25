package jwt_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

// kidProvider is an application-written Provider whose key id is whatever the
// test says: the module trusts the Provider's Keys() but must not let an odd
// id turn into a token it cannot verify, or into a panic.
type kidProvider struct {
	base authcore.Provider
	kid  string
}

type kidKeys struct {
	authcore.Keys
	kid string
}

func (k kidKeys) KeyID() string { return k.kid }

func (p kidProvider) Config() authcore.Config { return p.base.Config() }
func (p kidProvider) Logger() authcore.Logger { return p.base.Logger() }
func (p kidProvider) Keys() authcore.Keys     { return kidKeys{p.base.Keys(), p.kid} }

// Whatever key id the Provider reports, the module either refuses to be built,
// refuses to issue, or issues tokens that verify. A pair it hands out that its
// own verifier then rejects would lock every user out with no error at the
// issuing side.
func TestHostile_KidProvider_issuedTokensAlwaysVerifyOrIssuingFails(t *testing.T) {
	e := newEnv(t)
	for name, kid := range map[string]string{
		"empty":               "",
		"unicode":             "ключ-\U0001f511",
		"combining sequence":  "é",
		"contains dots":       "a.b.c",
		"contains quote":      `a"b`,
		"contains backslash":  `a\b`,
		"contains newline":    "a\nb",
		"contains NUL":        "a\x00b",
		"invalid UTF-8":       "a\xffb",
		"bidi override":       "a‮b",
		"1 KiB":               strings.Repeat("k", 1<<10),
		"7 KiB":               strings.Repeat("k", 7<<10),
		"100 KiB":             strings.Repeat("k", 100<<10),
		"looks like a number": "1234567890",
		"JSON-looking":        `{"kid":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			m, err := jwt.New[extra](kidProvider{e.prov, kid})
			if err != nil {
				return // refused at construction: fine
			}
			pair, err := m.CreateTokens(subject, extra{Role: "user"})
			if err != nil {
				return // refused at issuing: fine
			}
			if _, err := m.VerifyAccessToken(pair.AccessToken); err != nil {
				t.Errorf("issued access token fails the module's own verification: %v", err)
			}
			if _, err := m.RotateTokens(pair.RefreshToken, extra{}); err != nil {
				t.Errorf("issued refresh token fails the module's own rotation: %v", err)
			}
		})
	}
}

// A key id that is not valid UTF-8 cannot survive the JSON header, so the
// module refuses it when it is built instead of issuing tokens it would reject.
func TestHostile_KidProvider_invalidUTF8KidIsRefusedAtConstruction(t *testing.T) {
	e := newEnv(t)
	for _, kid := range []string{"a\xffb", "\xc0\xaf", "\xed\xa0\x80"} {
		if _, err := jwt.New[extra](kidProvider{e.prov, kid}); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("jwt.New with kid %q = %v, want ErrInvalidConfig", kid, err)
		}
	}
}

// Previous keys are indexed by a kid derived from the key. Listing the same
// key twice, or a key whose derived id equals the id the Provider reports,
// must not silently replace the current key in the verification set.
func TestHostile_KidProvider_previousKeysCannotShadowTheCurrentKid(t *testing.T) {
	e := newEnv(t)
	owner := newEnv(t) // a second deployment: its key is "previous" for the first
	prev := owner.pub

	// The same previous key listed twice is harmless, and the module still
	// verifies its own tokens.
	m, err := jwt.New[extra](e.prov, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{prev, prev}})
	if err != nil {
		t.Fatalf("a previous key listed twice was refused: %v", err)
	}
	pair, err := m.CreateTokens(subject, extra{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("own token refused after listing a previous key twice: %v", err)
	}

	// A Provider that reports the id of a previous key is refused: otherwise
	// the previous key would replace the current one in the key set.
	if _, err := jwt.New[extra](kidProvider{e.prov, owner.kid}, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{prev}}); !errors.Is(err, jwt.ErrInvalidConfig) {
		t.Fatalf("jwt.New with a Provider kid equal to a previous key's id = %v, want ErrInvalidConfig", err)
	}
}
