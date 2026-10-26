package jwsheader_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/jwsheader"
)

// A header that cannot be decoded is left to the signature parser, which owns
// reporting it; the critical-extension check must not guess at it.
func TestRejectCriticalLeavesUndecodableHeadersAlone(t *testing.T) {
	const header = "eyJjcml0IjpbImV4cCJdfQ"   // {"crit":["exp"]}
	const padded = "eyJjcml0IjpbImV4cCJdfSAg" // the same header plus two spaces, so whole quanta decode to complete JSON
	if err := jwsheader.RejectCritical(header + ".x.y"); !errors.Is(err, jwsheader.ErrCritical) {
		t.Fatalf("control: a well-formed crit header must be refused, got %v", err)
	}
	for name, tok := range map[string]string{
		"no separator":        header,
		"garbage after":       padded + "!.x.y",
		"not JSON after trim": "bm90IGpzb24.x.y",
	} {
		if err := jwsheader.RejectCritical(tok); err != nil {
			t.Errorf("%s: got %v, want nil", name, err)
		}
	}
}
