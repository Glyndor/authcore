// Package recoverytest holds the fixtures shared by the tests of recovery and
// of its subpackages (leftovers, wait): a silent and a recording logger, a
// published key set, and staging directories cut from one. It imports no
// production recovery code, so any of them can use it.
package recoverytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/fsguard"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// SilentLog discards everything it is given.
type SilentLog struct{}

// Info discards the message.
func (SilentLog) Info(string, ...any) {}

// Warn discards the message.
func (SilentLog) Warn(string, ...any) {}

// RecordingLog keeps every Warn, formatted as the message followed by its
// arguments.
type RecordingLog struct {
	mu    sync.Mutex
	Warns []string
}

// Info discards the message.
func (l *RecordingLog) Info(string, ...any) {}

// Warn records the message and its arguments.
func (l *RecordingLog) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = fmt.Sprintf("%v", a)
	}
	l.Warns = append(l.Warns, strings.TrimSpace(msg+" "+strings.Join(parts, " ")))
}

// WarnContains reports whether any recorded Warn contains needle.
func (l *RecordingLog) WarnContains(needle string) bool {
	return l.CountWarns(needle) > 0
}

// CountWarns counts the recorded Warns that contain needle.
func (l *RecordingLog) CountWarns(needle string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, w := range l.Warns {
		if strings.Contains(w, needle) {
			n++
		}
	}
	return n
}

// must returns v, or panics when err is set. The crypto calls below cannot
// fail with the system random source, so they are not worth a branch each.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// SeedKeys stands in for a published key set: it writes a valid, complete set
// of the three key files into dir (creating it) with the modes the key manager
// gives them, and nothing else.
func SeedKeys(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(0, err)
	secret := make([]byte, layout.RefreshSecretLen)
	must(rand.Read(secret))
	for name, f := range map[string]struct {
		data []byte
		perm os.FileMode
	}{
		layout.FilePrivateKey:    {must(pemcodec.EncodePrivateKeyPEM(priv)), 0600},
		layout.FilePublicKey:     {must(pemcodec.EncodePublicKeyPEM(pub)), 0644},
		layout.FileRefreshSecret: {[]byte(hex.EncodeToString(secret) + "\n"), 0600},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), f.data, f.perm); err != nil {
			return err
		}
	}
	return nil
}

// MustSeed seeds a published key set into dir and returns dir.
func MustSeed(t testing.TB, dir string) string {
	t.Helper()
	if err := SeedKeys(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// PosixOnly skips the test on Windows, where hard links and the file
// semantics recovery relies on are not available.
func PosixOnly(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}
}

// CopyFile copies src to dst with mode 0600.
func CopyFile(t testing.TB, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil { // #nosec G703 -- test fixture path
		t.Fatalf("write %s: %v", dst, err)
	}
}

// StagingFrom copies the three key files of the set in src into a new
// .staging-<name> directory inside dir and returns its path.
func StagingFrom(t testing.TB, dir, name, src string) string {
	t.Helper()
	staging := filepath.Join(dir, layout.StagingPrefix+name)
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range layout.KeyFileNames() {
		CopyFile(t, filepath.Join(src, f), filepath.Join(staging, f))
	}
	return staging
}

// Complete reports whether dir holds a complete key set.
func Complete(t testing.TB, dir string) bool {
	t.Helper()
	state, err := fsguard.InspectKeySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return state == fsguard.SetComplete
}
