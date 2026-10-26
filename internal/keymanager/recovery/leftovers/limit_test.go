package leftovers_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/recovery/leftovers"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// At most eight staging directories get a line of their own; the rest are
// counted in one more line.
func TestReport_EightIsTheLimitForIndividualLines(t *testing.T) {
	cases := []struct {
		dirs, lines int
		summary     string
	}{
		{7, 7, ""},
		{8, 8, ""},
		{9, 9, "and 1 more staging directories (9 in total)"},
		{11, 9, "and 3 more staging directories (11 in total)"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d directories", c.dirs), func(t *testing.T) {
			dir := recoverytest.MustSeed(t, t.TempDir())
			for i := 0; i < c.dirs; i++ {
				recoverytest.StagingFrom(t, dir, fmt.Sprintf("%016d", i), dir)
			}
			var log formatted

			leftovers.Report(dir, &log)

			if len(log.lines) != c.lines {
				t.Fatalf("%d warnings, want %d: %q", len(log.lines), c.lines, log.lines)
			}
			hasSummary := strings.Contains(log.lines[len(log.lines)-1], "more staging directories")
			if hasSummary != (c.summary != "") || (c.summary != "" && !strings.Contains(log.lines[len(log.lines)-1], c.summary)) {
				t.Fatalf("summary line mismatch, want %q in %q", c.summary, log.lines)
			}
		})
	}
}

// formatted keeps each warning as fmt would print it.
type formatted struct{ lines []string }

func (*formatted) Info(string, ...any) {}

func (f *formatted) Warn(msg string, args ...any) {
	f.lines = append(f.lines, fmt.Sprintf(msg, args...))
}
