package confusion

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// A secret of another kind that was hashed with the same key must not verify
// as an API key: Verify checks the shape of the key before it compares.
func TestMisuse_Confusion_apikeyVerifyRequiresTheGeneratedShape(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, err := jwt.New[struct{}](e.AC)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := j.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := j.HashRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if ak.Verify(pair.RefreshToken, stored) {
		t.Error("apikey.Verify accepted a refresh token against its stored hash")
	}
	for _, key := range []string{"", "ak", "ak_", "ak__", "ak_x_y", strings.ToUpper(pair.RefreshToken)} {
		h, err := ak.Hash(key)
		if err != nil {
			t.Fatal(err)
		}
		if ak.Verify(key, h) {
			t.Errorf("apikey.Verify accepted %q against its own hash", key)
		}
	}
}

// A key produced by Generate keeps verifying.
func TestMisuse_Confusion_apikeyVerifyStillAcceptsGeneratedKeys(t *testing.T) {
	e := hostiletest.NewEnv(t)
	ak, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ak.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !ak.Verify(g.Key, g.Hash) {
		t.Error("a generated key no longer verifies")
	}
	if ak.Verify(g.Key, "") {
		t.Error("a generated key verified against an empty hash")
	}
}
