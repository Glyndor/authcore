package leftovers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// seedStagings creates n staging directories holding copies of the published
// keys and returns the directory.
func seedStagings(t *testing.T, n int) string {
	t.Helper()
	dir := recoverytest.MustSeed(t, t.TempDir())
	for i := 0; i < n; i++ {
		recoverytest.StagingFrom(t, dir, fmt.Sprintf("%016d", i), dir)
	}
	return dir
}

func TestReport_aFewStagingDirectoriesAreEachReportedWithNoSummary(t *testing.T) {
	log := &captureLog{}
	Report(seedStagings(t, maxReported), log)

	if len(log.lines) != maxReported {
		t.Fatalf("got %d warnings, want %d: %v", len(log.lines), maxReported, log.lines)
	}
	for _, line := range log.lines {
		if strings.Contains(line, "more") {
			t.Errorf("a summary appeared with nothing left to summarise: %v", log.lines)
		}
	}
}

func TestReport_manyStagingDirectoriesAreSummarisedButStillReported(t *testing.T) {
	const total = maxReported + 12
	log := &captureLog{}
	Report(seedStagings(t, total), log)

	if len(log.lines) != maxReported+1 {
		t.Fatalf("got %d warnings, want %d (the first %d and one summary): %v",
			len(log.lines), maxReported+1, maxReported, log.lines)
	}
	last := log.lines[len(log.lines)-1]
	for _, want := range []string{"and 12 more", fmt.Sprint(total), "staging", "can be deleted"} {
		if !strings.Contains(last, want) {
			t.Errorf("the summary does not say %q: %s", want, last)
		}
	}
}
