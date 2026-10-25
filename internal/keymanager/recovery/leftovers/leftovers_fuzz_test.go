package leftovers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// captureLog keeps every warning the scan emits, formatted.
type captureLog struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureLog) Info(string, ...any) {}

func (c *captureLog) Warn(msg string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(msg, args...))
}

// FuzzReportStagingName drives the leftover scan with arbitrary directory
// entry names. It must never panic, and a name must never put a raw control
// character, a line break or an invalid byte sequence into a log line.
func FuzzReportStagingName(f *testing.F) {
	f.Add("abcdef0123456789")
	f.Add("..")
	f.Add("x\n[ERROR] forged")
	f.Add("\x1b[2J\r")
	f.Add("\xff\xfe\xc0\x80")
	f.Add("%s%d%n")
	f.Add(strings.Repeat("n", 200))

	f.Fuzz(func(t *testing.T, suffix string) {
		if strings.ContainsAny(suffix, "/\x00") || len(layout.StagingPrefix+suffix) > 255 {
			t.Skip("not a valid directory entry name")
		}
		dir := t.TempDir()
		staging := filepath.Join(dir, layout.StagingPrefix+suffix)
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Skipf("filesystem refuses the name: %v", err)
		}
		for _, name := range layout.KeyFileNames() {
			if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		log := &captureLog{}
		Report(dir, log)

		if len(log.lines) != 1 {
			t.Fatalf("expected exactly one warning for one staging directory, got %d", len(log.lines))
		}
		for _, line := range log.lines {
			for _, r := range line {
				if r == '\n' || r == '\r' || r == 0x1b || r == 0xfffd || (r < 0x20 && r != '\t') {
					t.Fatalf("a directory name put %q into a log line: %q", r, line)
				}
			}
		}
	})
}
