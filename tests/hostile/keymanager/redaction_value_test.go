//go:build unix

package hostile

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// A KeyManager copied by value must print as redacted as the pointer does.
func TestHostile_KeyManagerValuePrintsRedacted(t *testing.T) {
	s := newSet(t)
	km, err := keymanager.FromKeys(s.priv, s.pub, s.secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%c", "%e", "%t", "%z", "%x", "%d"} {
		assertNoLeak(t, "Sprintf("+verb+") of a KeyManager value", []keySet{s}, fmt.Sprintf(verb, *km))
	}
}
