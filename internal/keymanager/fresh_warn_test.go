package keymanager_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// recordingLogger satisfies the unexported keymanager.logger interface and
// captures Warn entries so a test can assert the exact log surface keymanager
// produces, not just "some entry was made". Format strings are resolved with
// the supplied args before storage, matching what a real logger would print.
//
// Mutex-protected so the test is usable from goroutines if a future test
// decides to drive New concurrently.
type recordingLogger struct {
	mu    sync.Mutex
	warns []string
	infos []string
}

func (l *recordingLogger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, fmt.Sprintf(msg, args...))
}

func (l *recordingLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprintf(msg, args...))
}

// freshGenerationTag is the substring operators wire into monitoring to
// catch an unexpected fresh-key-set generation. Asserting against the exact
// fragment, not the whole message, keeps the test stable across copy edits.
const freshGenerationTag = "generating a fresh key set"

// freshWarns returns the captured Warn entries that name the fresh-generation
// warning, so a test can ignore unrelated warnings (mode, metadata, leftover
// staging) that the load path also produces.
func (l *recordingLogger) freshWarns() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []string{}
	for _, w := range l.warns {
		if strings.Contains(w, freshGenerationTag) {
			out = append(out, w)
		}
	}
	return out
}

// TestNew_warnsOnFreshGeneration pins the contract that operators wire into
// monitoring: when New generates a brand-new key set because KeysDir was
// empty, a Warn entry must reach the logger before any key material is
// produced. Without the warning, the silent regeneration that takes down
// every issued token and every stored credential hash is invisible to anyone
// not reading the full Info stream.
//
// The assertion checks the formatted entry, not just the call count, so a
// future change that emits a Warn for some other reason does not silently
// satisfy the contract.
func TestNew_warnsOnFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	log := &recordingLogger{}

	if _, err := keymanager.New(dir, log); err != nil {
		t.Fatalf("New() error = %v", err)
	}

	fresh := log.freshWarns()
	if len(fresh) == 0 {
		t.Fatalf("expected a Warn naming %q, captured entries: warns=%v infos=%v",
			freshGenerationTag, log.warns, log.infos)
	}
	for _, w := range fresh {
		if !strings.Contains(w, dir) {
			t.Errorf("fresh-generation Warn should name the KeysDir %q, got: %q", dir, w)
		}
	}
}

// TestNew_doesNotWarnOnFreshGenerationWhenKeysAlreadyExist is the acceptance
// pair: a New call against an already-populated KeysDir must not emit the
// fresh-generation warning. The warning is reserved for the moment of
// regeneration, not for every startup.
func TestNew_doesNotWarnOnFreshGenerationWhenKeysAlreadyExist(t *testing.T) {
	dir := t.TempDir()
	seed := &recordingLogger{}
	if _, err := keymanager.New(dir, seed); err != nil {
		t.Fatalf("seed New() error = %v", err)
	}

	log := &recordingLogger{}
	if _, err := keymanager.New(dir, log); err != nil {
		t.Fatalf("second New() error = %v", err)
	}

	if got := len(log.freshWarns()); got != 0 {
		t.Errorf("expected no fresh-generation Warn on a populated KeysDir, got %d: %v",
			got, log.freshWarns())
	}
}
