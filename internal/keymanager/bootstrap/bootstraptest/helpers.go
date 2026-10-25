package bootstraptest

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

// Recorder keeps every message the key manager logs, formatted.
type Recorder struct {
	mu    sync.Mutex
	Warns []string
	Infos []string
}

// Info records the formatted message.
func (r *Recorder) Info(msg string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Infos = append(r.Infos, fmt.Sprintf(msg, args...))
}

// Warn records the formatted message.
func (r *Recorder) Warn(msg string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Warns = append(r.Warns, fmt.Sprintf(msg, args...))
}

// Warned reports whether any warning contains fragment.
func (r *Recorder) Warned(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.Warns {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

// CountWarns counts the warnings that contain fragment.
func (r *Recorder) CountWarns(fragment string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, w := range r.Warns {
		if strings.Contains(w, fragment) {
			n++
		}
	}
	return n
}

// PosixOnly skips the test where Unix permission bits and hard links do not exist.
func PosixOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits and hard links are required")
	}
}

// NotRoot skips the test for root, which ignores directory mode bits.
func NotRoot(t *testing.T) {
	t.Helper()
	PosixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
}

// WithFault installs fn as the fault seam for the test.
func WithFault(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := seams.FaultAt
	seams.FaultAt = fn
	t.Cleanup(func() { seams.FaultAt = prev })
}

// ReadFile returns the named file of dir or fails the test.
func ReadFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

// OpenOK runs Open and fails the test on error.
func OpenOK(t *testing.T, dir string, log *Recorder) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	priv, pub, secret, err := bootstrap.Open(dir, log)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	return priv, pub, secret
}

// TestLogger satisfies the unexported keymanager.logger interface via
// structural typing and forwards entries to the test log.
type TestLogger struct{ T *testing.T }

// Info forwards the entry to the test log.
func (l TestLogger) Info(msg string, args ...any) { l.T.Logf("[INFO] "+msg, args...) }

// Warn forwards the entry to the test log.
func (l TestLogger) Warn(msg string, args ...any) { l.T.Logf("[WARN] "+msg, args...) }

// SeedValidDir returns a key directory holding a complete, valid set of key
// files. The oversized-file tests start from one because New checks the
// directory for consistency *before* it loads anything: a directory with two of
// the three files is rejected as partially populated and never reaches the
// capped reader at all.
func SeedValidDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := New(dir, TestLogger{t}); err != nil {
		t.Fatalf("seed New(): %v", err)
	}
	return dir
}

// SilentLog is a logger that discards every message.
type SilentLog struct{}

// Info discards the message.
func (SilentLog) Info(string, ...any) {}

// Warn discards the message.
func (SilentLog) Warn(string, ...any) {}

// Error discards the message.
func (SilentLog) Error(string, ...any) {}

// Debug discards the message.
func (SilentLog) Debug(string, ...any) {}

// RecordingLog keeps every Warn entry it receives, unformatted.
type RecordingLog struct {
	mu      sync.Mutex
	Entries []LogEntry
}

// LogEntry is one recorded Warn call.
type LogEntry struct {
	Msg  string
	Args []any
}

// Info discards the message.
func (l *RecordingLog) Info(msg string, args ...any) {}

// Error discards the message.
func (l *RecordingLog) Error(msg string, args ...any) {}

// Warn records the entry.
func (l *RecordingLog) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Entries = append(l.Entries, LogEntry{msg, args})
}

// WarnContains reports whether any recorded Warn contains needle once formatted.
func (l *RecordingLog) WarnContains(needle string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.Entries {
		if strings.Contains(FormatEntry(w), needle) {
			return true
		}
	}
	return false
}

// FormatEntry renders an entry as its message followed by its arguments.
func FormatEntry(e LogEntry) string {
	if len(e.Args) == 0 {
		return e.Msg
	}
	parts := make([]string, len(e.Args))
	for i, a := range e.Args {
		parts[i] = fmt.Sprintf("%v", a)
	}
	return e.Msg + " " + strings.Join(parts, " ")
}

// ReadSet returns the three key files of dir or fails the test.
func ReadSet(t *testing.T, dir string) [3][]byte {
	t.Helper()
	return ReadSetMissing(t, dir, false)
}

// ReadPublishedSet is ReadSet that tolerates files not yet published.
func ReadPublishedSet(t *testing.T, dir string) [3][]byte {
	t.Helper()
	return ReadSetMissing(t, dir, true)
}

// ReadSetMissing reads the three key files, optionally tolerating absent ones.
func ReadSetMissing(t *testing.T, dir string, allowMissing bool) [3][]byte {
	t.Helper()
	var out [3][]byte
	for i, name := range layout.KeyFileNames() {
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

// ListStagingDirs returns the real staging directories left in dir.
func ListStagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), layout.StagingPrefix) {
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

// WithFaultAt installs fn as seams.FaultAt for the test; nil means no fault.
func WithFaultAt(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := seams.FaultAt
	if fn == nil {
		seams.FaultAt = func(string) error { return nil }
	} else {
		seams.FaultAt = fn
	}
	t.Cleanup(func() { seams.FaultAt = prev })
}

// WithLinkFile installs fn as seams.LinkFile for the test.
func WithLinkFile(t *testing.T, fn func(string, string) error) {
	t.Helper()
	prev := seams.LinkFile
	seams.LinkFile = fn
	t.Cleanup(func() { seams.LinkFile = prev })
}

// CopyFile copies src to dst with mode 0600 or fails the test.
func CopyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil { // #nosec G703 -- test fixture path
		t.Fatalf("write %s: %v", dst, err)
	}
}

// MustHexDecode decodes lowercase hex, ignoring trailing newlines, or fails the test.
func MustHexDecode(t *testing.T, b []byte) []byte {
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
