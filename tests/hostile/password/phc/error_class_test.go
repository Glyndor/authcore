package phc

import (
	"errors"
	"strconv"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// A refused stored hash is ErrInvalidHash and nothing else: a caller that
// branches on ErrWeakPassword or ErrInvalidConfig must not take the corrupted
// row for a weak password or a bad configuration. The underlying parse error
// stays reachable behind it.
func TestHostile_PHC_refusedHashIsOnlyErrInvalidHash(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	good, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	p := hostiletest.Parts(t, good)
	tooBig := hostiletest.Join("", "argon2id", "v=19", "m=99999999999,t=1,p=1", p[4], p[5])
	for name, hash := range map[string]string{"garbage": "not-a-hash", "overflowing memory": tooBig} {
		ok, err := m.Verify(hostiletest.Strong, hash)
		if ok || !errors.Is(err, password.ErrInvalidHash) {
			t.Fatalf("%s: Verify = %v, %v; want false, ErrInvalidHash", name, ok, err)
		}
		for other, sentinel := range map[string]error{
			"ErrWeakPassword":          password.ErrWeakPassword,
			"ErrInvalidConfig":         password.ErrInvalidConfig,
			"ErrNonPrintableCharacter": password.ErrNonPrintableCharacter,
		} {
			if errors.Is(err, sentinel) {
				t.Errorf("%s: the refusal also matches %s", name, other)
			}
		}
	}
	_, err = m.Verify(hostiletest.Strong, tooBig)
	if !errors.Is(err, strconv.ErrRange) {
		t.Errorf("overflowing memory: cause not reachable through the error chain: %v", err)
	}
}
