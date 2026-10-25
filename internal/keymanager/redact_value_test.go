package keymanager

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/redact"
)

// A KeyManager copied out of its pointer prints as redacted as the pointer
// does, on every verb, including the ones the type does not support.
func TestFormattingAManagerValueRedactsEveryVerb(t *testing.T) {
	km := sentinelKeys()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%c", "%e", "%t", "%x", "%d", "%z"} {
		out := fmt.Sprintf(verb, *km)
		for _, b := range [][]byte{km.material.privateKey, km.material.refreshSecret} {
			if leak := fmt.Sprintf("%d %d %d %d", b[0], b[1], b[2], b[3]); strings.Contains(out, leak) {
				t.Errorf("%s of a value leaks key bytes: %s", verb, out)
			}
		}
	}
	if out := fmt.Sprintf("%v", *km); !strings.Contains(out, redact.Placeholder) {
		t.Errorf("a value is not described as redacted: %s", out)
	}
}
