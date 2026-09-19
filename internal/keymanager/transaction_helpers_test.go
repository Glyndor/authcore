package keymanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Helpers shared by transaction_internal_test.go. Pulled into a separate file
// so the per-test logic stays readable.

type recordingLog struct {
	mu   sync.Mutex
	warn []logEntry
}

type logEntry struct {
	msg  string
	args []any
}

func (l *recordingLog) Info(msg string, args ...any)  {}
func (l *recordingLog) Error(msg string, args ...any) {}

func (l *recordingLog) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warn = append(l.warn, logEntry{msg, args})
}

func (l *recordingLog) warnContains(needle string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.warn {
		if strings.Contains(formatEntry(w), needle) {
			return true
		}
	}
	return false
}

func formatEntry(e logEntry) string {
	if len(e.args) == 0 {
		return e.msg
	}
	parts := make([]string, len(e.args))
	for i, a := range e.args {
		parts[i] = fmt.Sprintf("%v", a)
	}
	return e.msg + " " + strings.Join(parts, " ")
}

func readSet(t *testing.T, dir string) [3][]byte {
	t.Helper()
	return readSetMissing(t, dir, false)
}

func readPublishedSet(t *testing.T, dir string) [3][]byte {
	t.Helper()
	return readSetMissing(t, dir, true)
}

func readSetMissing(t *testing.T, dir string, allowMissing bool) [3][]byte {
	t.Helper()
	var out [3][]byte
	for i, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test fixture
		if err != nil {
			if allowMissing && os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", name, err)
		}
		out[i] = data
	}
	return out
}

func listStagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), stagingPrefix) {
			continue
		}
		lst, err := os.Lstat(filepath.Join(dir, e.Name())) // #nosec G304 -- test fixture
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

func withFaultAt(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := faultAt
	if fn == nil {
		faultAt = func(string) error { return nil }
	} else {
		faultAt = fn
	}
	t.Cleanup(func() { faultAt = prev })
}

func withLinkFile(t *testing.T, fn func(string, string) error) {
	t.Helper()
	prev := linkFile
	linkFile = fn
	t.Cleanup(func() { linkFile = prev })
}

func metaEqual(a, b *metadata) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Format == b.Format && a.Created == b.Created && a.KeyID == b.KeyID
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func mustHexDecode(t *testing.T, b []byte) []byte {
	t.Helper()
	const hexchars = "0123456789abcdef"
	lookup := func(c byte) byte {
		for i := 0; i < len(hexchars); i++ {
			if hexchars[i] == c {
				return byte(i)
			}
		}
		t.Fatalf("non-hex byte %q", c)
		return 0
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	if len(b)%2 != 0 {
		t.Fatalf("odd hex length: %d", len(b))
	}
	out := make([]byte, len(b)/2)
	for i := 0; i < len(out); i++ {
		out[i] = lookup(b[2*i])<<4 | lookup(b[2*i+1])
	}
	return out
}
