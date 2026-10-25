//go:build unix

package redaction

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// A KeyManager copied by value must print as redacted as the pointer does.
func TestHostile_KeyManagerValuePrintsRedacted(t *testing.T) {
	s := hostiletest.NewSet(t)
	km, err := keymanager.FromKeys(s.Priv, s.Pub, s.Secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%c", "%e", "%t", "%z", "%x", "%d"} {
		hostiletest.AssertNoLeak(t, "Sprintf("+verb+") of a KeyManager value", []hostiletest.KeySet{s}, fmt.Sprintf(verb, *km))
	}
}
