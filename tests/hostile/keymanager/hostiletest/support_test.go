//go:build unix

package hostiletest_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// fakeTB wraps a real test and records failures instead of ending it, so the
// failure branch of a helper can be asserted. Fatal and Fatalf stop the
// helper's goroutine like the real ones do.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatal(...any) {
	f.failed = true
	runtime.Goexit()
}

func (f *fakeTB) Fatalf(string, ...any) {
	f.failed = true
	runtime.Goexit()
}

func (f *fakeTB) Errorf(string, ...any) { f.failed = true }

// fails runs fn against a fakeTB on its own goroutine and reports whether fn
// failed.
func fails(t testing.TB, fn func(tb testing.TB)) bool {
	t.Helper()
	f := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	return f.failed
}

func TestKeySetFilesRoundTrip(t *testing.T) {
	s := hostiletest.NewSet(t)
	dir := t.TempDir()
	s.WriteFiles(t, dir)
	if got := hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey)); string(got) != string(s.PrivPEM) {
		t.Fatal("private key file differs from the set")
	}
	if hostiletest.ModeOf(t, filepath.Join(dir, layout.FilePrivateKey)).Perm() != 0o600 {
		t.Fatal("private key is not 0600")
	}
	if len(s.KeyID()) != 16 {
		t.Fatalf("key id %q", s.KeyID())
	}
	if len(s.Needles()) == 0 {
		t.Fatal("no needles")
	}
	hostiletest.AssertNoLeak(t, "clean text", []hostiletest.KeySet{s}, "nothing to see")
	if !fails(t, func(tb testing.TB) {
		hostiletest.AssertNoLeak(tb, "leaky text", []hostiletest.KeySet{s}, s.Needles()[0])
	}) {
		t.Fatal("a leak was not reported")
	}
}

func TestFileHelpersAndTheirFailures(t *testing.T) {
	dir := hostiletest.MustMkdir(t, filepath.Join(t.TempDir(), "a", "b"))
	file := filepath.Join(dir, "f")
	hostiletest.Put(t, file, []byte("x"), 0o640)
	if hostiletest.ModeOf(t, file).Perm() != 0o640 || string(hostiletest.Read(t, file)) != "x" {
		t.Fatal("Put or Read wrong")
	}
	link := filepath.Join(dir, "l")
	hostiletest.MustSymlink(t, file, link)
	if target, _ := os.Readlink(link); target != file {
		t.Fatalf("link points at %q", target)
	}
	missing := filepath.Join(dir, "missing", "x")
	for name, fn := range map[string]func(tb testing.TB){
		"Put":          func(tb testing.TB) { hostiletest.Put(tb, missing, nil, 0o600) },
		"Read":         func(tb testing.TB) { hostiletest.Read(tb, missing) },
		"MustMkdir":    func(tb testing.TB) { hostiletest.MustMkdir(tb, filepath.Join(file, "sub")) },
		"MustSymlink":  func(tb testing.TB) { hostiletest.MustSymlink(tb, file, link) },
		"ModeOf":       func(tb testing.TB) { hostiletest.ModeOf(tb, missing) },
		"Mkfifo":       func(tb testing.TB) { hostiletest.Mkfifo(tb, file) },
		"Mksocket":     func(tb testing.TB) { hostiletest.Mksocket(tb, missing) },
		"StagingDirs":  func(tb testing.TB) { hostiletest.StagingDirs(tb, missing) },
		"Tree":         func(tb testing.TB) { hostiletest.Tree(tb, missing) },
		"PublishedErr": func(tb testing.TB) { hostiletest.PublishedPrivate(tb, "/dev/null") },
	} {
		if !fails(t, fn) {
			t.Errorf("%s did not fail on bad input", name)
		}
	}
}

func TestOpenLoadedAndRefused(t *testing.T) {
	s := hostiletest.NewSet(t)
	other := hostiletest.NewSet(t)
	sb := hostiletest.NewSandbox(t)
	dir := sb.WithSet(t, s)
	r := hostiletest.Open(t, dir, true)
	hostiletest.Loaded(t, r, s)
	if !fails(t, func(tb testing.TB) { hostiletest.Loaded(tb, r, other) }) {
		t.Fatal("Loaded accepted another set")
	}
	if !fails(t, func(tb testing.TB) { hostiletest.Refused(tb, r) }) {
		t.Fatal("Refused accepted a success")
	}

	empty := hostiletest.NewSandbox(t)
	refused := hostiletest.Open(t, empty.KeysDir(t), true)
	hostiletest.Refused(t, refused, s)
	if !fails(t, func(tb testing.TB) { hostiletest.Loaded(tb, refused, s) }) {
		t.Fatal("Loaded accepted an error")
	}
	created := hostiletest.Open(t, empty.Keys, false)
	if created.Err != nil || created.Keys == nil || created.Log.Has("no such text") {
		t.Fatalf("writable open failed: %v", created.Err)
	}
	for _, level := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
		created.Log.Debug("d %d", 1)
		created.Log.Info("i")
		created.Log.Warn("w")
		created.Log.Error("e")
		if !created.Log.Has(level) {
			t.Fatalf("log has no %s line: %s", level, created.Log.All())
		}
	}
	if len(hostiletest.StagingDirs(t, empty.Keys)) != 0 {
		t.Fatal("a fresh store left staging directories")
	}
}

func TestBothModesRunsTwice(t *testing.T) {
	var modes []bool
	hostiletest.BothModes(t, func(_ *testing.T, loadOnly bool) { modes = append(modes, loadOnly) })
	if len(modes) != 2 || modes[0] || !modes[1] {
		t.Fatalf("modes = %v", modes)
	}
}

func TestTreeAndAssertSame(t *testing.T) {
	root := t.TempDir()
	hostiletest.Put(t, filepath.Join(root, "f"), []byte("x"), 0o600)
	hostiletest.MustMkdir(t, filepath.Join(root, "d"))
	hostiletest.MustSymlink(t, "f", filepath.Join(root, "l"))
	hostiletest.Mkfifo(t, filepath.Join(root, "p"))
	big := filepath.Join(root, "big")
	hostiletest.Put(t, big, make([]byte, 1<<20+1), 0o600)
	locked := filepath.Join(root, "locked")
	hostiletest.Put(t, locked, []byte("s"), 0o000)

	before := hostiletest.Tree(t, root)
	for _, name := range []string{"f", "d", "l", "p", "big", "locked", "."} {
		if _, ok := before[name]; !ok {
			t.Errorf("snapshot has no %q", name)
		}
	}
	if !strings.HasPrefix(string(before["l"]), "link->") || !strings.HasPrefix(string(before["p"]), "special") ||
		!strings.HasPrefix(string(before["big"]), "big file") {
		t.Fatalf("unexpected kinds: %v", before)
	}
	if os.Geteuid() != 0 && !strings.HasPrefix(string(before["locked"]), "unreadable") {
		t.Fatalf("locked file kind %q", before["locked"])
	}
	hostiletest.AssertSame(t, "unchanged", before, hostiletest.Tree(t, root))
	hostiletest.RestoreDirTree(root)

	hostiletest.Put(t, filepath.Join(root, "f"), []byte("changed"), 0o600)
	if err := os.Remove(filepath.Join(root, "d")); err != nil {
		t.Fatal(err)
	}
	hostiletest.Put(t, filepath.Join(root, "new"), []byte("n"), 0o600)
	after := hostiletest.Tree(t, root)
	if !fails(t, func(tb testing.TB) { hostiletest.AssertSame(tb, "changed", before, after) }) {
		t.Fatal("AssertSame missed the differences")
	}

	hostiletest.Put(t, filepath.Join(root, layout.FileGitignore), []byte("x"), 0o600)
	if _, ok := hostiletest.KeyTree(t, root)[layout.FileGitignore]; ok {
		t.Fatal("KeyTree kept the gitignore entry")
	}
}

func TestStagingDirsListsOnlyStaging(t *testing.T) {
	dir := t.TempDir()
	hostiletest.MustMkdir(t, filepath.Join(dir, layout.StagingPrefix+"one"))
	hostiletest.MustMkdir(t, filepath.Join(dir, "other"))
	got := hostiletest.StagingDirs(t, dir)
	if len(got) != 1 || got[0] != layout.StagingPrefix+"one" {
		t.Fatalf("StagingDirs = %v", got)
	}
}

func TestModeHelpers(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	dir := hostiletest.MustMkdir(t, filepath.Join(t.TempDir(), "d"))
	t.Run("locked", func(t *testing.T) {
		hostiletest.RestoreMode(t, dir)
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
	})
	if hostiletest.ModeOf(t, dir).Perm() != 0o700 {
		t.Fatal("RestoreMode did not reopen the directory")
	}
}

func TestSandbox(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	if _, err := os.Stat(sb.Keys); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("KeysDir exists before KeysDir(): %v", err)
	}
	if _, err := os.Stat(sb.Outside); err != nil {
		t.Fatal(err)
	}
	if hostiletest.ModeOf(t, sb.KeysDir(t)).Perm() != 0o700 {
		t.Fatal("KeysDir is not 0700")
	}
	if hostiletest.PublishedPrivate(t, sb.Keys) != nil {
		t.Fatal("empty KeysDir has a private key")
	}
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
	if string(hostiletest.PublishedPrivate(t, dir)) != string(s.PrivPEM) {
		t.Fatal("WithSet did not publish the set")
	}
}

func TestFilesystemNodes(t *testing.T) {
	dir := t.TempDir()
	hostiletest.Mkfifo(t, filepath.Join(dir, "p"))
	hostiletest.Mksocket(t, filepath.Join(dir, "s"))
	if hostiletest.ModeOf(t, filepath.Join(dir, "p")).Type()&os.ModeNamedPipe == 0 {
		t.Fatal("not a pipe")
	}
	if hostiletest.ModeOf(t, filepath.Join(dir, "s")).Type()&os.ModeSocket == 0 {
		t.Fatal("not a socket")
	}
}

func TestSeamsAreInstalledAndRestored(t *testing.T) {
	prevFault, prevLink := seams.FaultAt, seams.LinkFile
	t.Run("installed", func(t *testing.T) {
		hostiletest.CrashAt(t, "p1")
		if seams.FaultAt("other") != nil {
			t.Fatal("crashed at the wrong point")
		}
		if seams.FaultAt("p1") == nil {
			t.Fatal("did not crash at the named point")
		}
		if seams.FaultAt("p1") != nil {
			t.Fatal("crashed twice")
		}
		hostiletest.SetFault(t, func(string) error { return errors.New("x") })
		if seams.FaultAt("any") == nil {
			t.Fatal("SetFault not installed")
		}
		hostiletest.SetLink(t, func(_, _ string) error { return errors.New("link") })
		if seams.LinkFile("a", "b") == nil {
			t.Fatal("SetLink not installed")
		}
	})
	if seams.FaultAt == nil && prevFault != nil || seams.LinkFile == nil && prevLink != nil {
		t.Fatal("seams were not restored")
	}
	if prevFault != nil && seams.FaultAt("never") != prevFault("never") {
		t.Fatal("fault seam changed after cleanup")
	}
}
