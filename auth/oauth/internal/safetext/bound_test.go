package safetext_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

func TestQuoteKeepsExactlyTheDefaultBound(t *testing.T) {
	t.Parallel()
	if got := safetext.Quote(strings.Repeat("a", 256)); strings.Contains(got, "…") {
		t.Errorf("256 bytes must pass whole: %q", got)
	}
	if got := safetext.Quote(strings.Repeat("a", 257)); got != `"`+strings.Repeat("a", 256)+`…"` {
		t.Errorf("257 bytes must be cut at 256: %q", got)
	}
}
