//go:build unix

// Package staging attacks the publish transaction: hard links, replaced files,
// and abandoned or foreign staging directories.
package staging

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 4: hard links, files replaced during publish, abandoned or foreign
// staging directories and staging directories with hostile names.

func TestHostile_Staging_hardLinksToExternalNonKeyFilesAreRefusedUntouched(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		for _, n := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
			victim := filepath.Join(sb.Outside, "victim-"+n)
			hostiletest.Put(t, victim, []byte("precious "+n+"\n"), 0o644)
			if err := os.Link(victim, filepath.Join(dir, n)); err != nil {
				t.Skipf("hard links unavailable here: %v", err)
			}
		}
		before := hostiletest.Tree(t, sb.Outside)

		hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly))

		hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
	})
}

func TestHostile_Staging_hardLinkedExternalCopyOfASetIsReadNeverRewritten(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.KeysDir(t)
	s.WriteFiles(t, sb.Outside)
	for _, n := range layout.KeyFileNames() {
		if err := os.Link(filepath.Join(sb.Outside, n), filepath.Join(dir, n)); err != nil {
			t.Skipf("hard links unavailable here: %v", err)
		}
	}
	before := hostiletest.Tree(t, sb.Outside)

	hostiletest.Loaded(t, hostiletest.Open(t, dir, true), s)
	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)

	hostiletest.AssertSame(t, "outside", before, hostiletest.Tree(t, sb.Outside))
}

func TestHostile_Staging_regularFilePlantedBetweenCheckAndLinkIsNeverOverwritten(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	dir := sb.KeysDir(t)
	planted := []byte("attacker owned, mode 0644\n")
	path := filepath.Join(dir, layout.FilePrivateKey)
	hostiletest.SetFault(t, func(point string) error {
		if point == "staged" {
			return os.WriteFile(path, planted, 0o644)
		}
		return nil
	})

	r := hostiletest.Open(t, dir, false) // waits out the publish deadline, about five seconds

	hostiletest.Refused(t, r)
	if !bytes.Equal(hostiletest.Read(t, path), planted) {
		t.Error("the planted file was overwritten by the freshly generated private key")
	}
	if _, err := os.Lstat(filepath.Join(dir, layout.FilePublicKey)); err == nil {
		t.Error("a public key was published beside a private key authcore did not write")
	}
}

func TestHostile_Staging_fileReplacedDuringPublishIsRefusedThenStaysRefused(t *testing.T) {
	cases := []struct {
		name, after, replaced string
	}{
		{"public replaced after private", "published-private", layout.FilePublicKey},
		{"secret replaced after public", "published-public", layout.FileRefreshSecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			foreign := []byte("not what authcore staged\n")
			path := filepath.Join(dir, c.replaced)
			hostiletest.SetFault(t, func(point string) error {
				if point == c.after {
					return os.WriteFile(path, foreign, 0o600)
				}
				return nil
			})

			first := hostiletest.Open(t, dir, false)
			hostiletest.Refused(t, first)
			if !strings.Contains(first.Err.Error(), "two different initialisations") {
				t.Errorf("the refusal does not say what is wrong: %v", first.Err)
			}

			hostiletest.SetFault(t, func(string) error { return nil })
			// The foreign bytes are not valid key material, so the next start
			// refuses too (as TwoInits while the set is partial, as a parse
			// error once it is complete) and never normalises them.
			hostiletest.Refused(t, hostiletest.Open(t, dir, false))
			if !bytes.Equal(hostiletest.Read(t, path), foreign) {
				t.Error("the foreign file was replaced by recovery")
			}
			if len(hostiletest.StagingDirs(t, dir)) == 0 {
				t.Error("the staging directory, the only copy of the staged keys, was deleted")
			}
		})
	}
}

// abandon leaves a complete, unpublished staging directory by crashing right
// after it was written, and returns its private key file bytes.
func abandon(t *testing.T, dir string) []byte {
	t.Helper()
	hostiletest.CrashAt(t, "staged")
	hostiletest.Refused(t, hostiletest.Open(t, dir, false))
	hostiletest.SetFault(t, func(string) error { return nil })
	names := hostiletest.StagingDirs(t, dir)
	if len(names) != 1 {
		t.Fatalf("expected one abandoned staging directory, got %v", names)
	}
	return hostiletest.Read(t, filepath.Join(dir, names[0], layout.FilePrivateKey))
}

func TestHostile_Staging_abandonedStagingIsNeverAdoptedByALaterSet(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	dir := sb.KeysDir(t)
	stagedPriv := abandon(t, dir)

	r := hostiletest.Open(t, dir, false)
	if r.Err != nil {
		t.Fatalf("a crash before any link must not block the next start: %v", r.Err)
	}
	if bytes.Equal(hostiletest.Read(t, filepath.Join(dir, layout.FilePrivateKey)), stagedPriv) {
		t.Fatal("the abandoned staging keys were published without ever being linked")
	}
	if !r.Log.Has("never published") {
		t.Errorf("the abandoned staging directory was not reported:\n%s", r.Log.All())
	}

	// Damage the published set into a partial one: the old staging holds a
	// different private key, so it must not be used to complete it.
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	hostiletest.Refused(t, hostiletest.Open(t, dir, false))
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s was recreated from a staging directory of another set", n)
		}
	}
}

// partialWith builds a KeysDir holding only the private key of s.
func partialWith(t *testing.T, sb hostiletest.Sandbox, s hostiletest.KeySet) string {
	t.Helper()
	dir := sb.KeysDir(t)
	hostiletest.Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
	return dir
}

// stage writes a staging directory called name holding s.
func stage(t *testing.T, dir, name string, s hostiletest.KeySet) string {
	t.Helper()
	st := hostiletest.MustMkdir(t, filepath.Join(dir, name))
	s.WriteFiles(t, st)
	return st
}

func TestHostile_Staging_foreignStagingContentIsNotAdopted(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, st string, mine hostiletest.KeySet)
	}{
		{"different private", func(t *testing.T, st string, _ hostiletest.KeySet) {
			hostiletest.Put(t, filepath.Join(st, layout.FilePrivateKey), hostiletest.NewSet(t).PrivPEM, 0o600)
		}},
		{"private is garbage", func(t *testing.T, st string, _ hostiletest.KeySet) {
			hostiletest.Put(t, filepath.Join(st, layout.FilePrivateKey), []byte("garbage"), 0o600)
		}},
		{"secret file missing", func(t *testing.T, st string, _ hostiletest.KeySet) {
			if err := os.Remove(filepath.Join(st, layout.FileRefreshSecret)); err != nil {
				t.Fatal(err)
			}
		}},
		{"public file is a fifo", func(t *testing.T, st string, _ hostiletest.KeySet) {
			p := filepath.Join(st, layout.FilePublicKey)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			hostiletest.Mkfifo(t, p)
		}},
		{"secret file is a directory", func(t *testing.T, st string, _ hostiletest.KeySet) {
			p := filepath.Join(st, layout.FileRefreshSecret)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			hostiletest.MustMkdir(t, p)
		}},
		{"private is a megabyte", func(t *testing.T, st string, mine hostiletest.KeySet) {
			hostiletest.Put(t, filepath.Join(st, layout.FilePrivateKey), append(append([]byte{}, mine.PrivPEM...), bytes.Repeat([]byte("x"), 1<<20)...), 0o600)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			mine := hostiletest.NewSet(t)
			dir := partialWith(t, sb, mine)
			st := stage(t, dir, layout.StagingPrefix+"foreign", mine)
			c.build(t, st, mine)

			hostiletest.Refused(t, hostiletest.Open(t, dir, false), mine)

			for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
				if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
					t.Errorf("%s was linked into KeysDir from the foreign staging directory", n)
				}
			}
		})
	}
}

func TestHostile_Staging_aMatchingStagingAmongForeignOnesIsTheOneAdopted(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	mine := hostiletest.NewSet(t)
	dir := partialWith(t, sb, mine)
	for i, name := range []string{".staging-0000", ".staging-zzzz"} {
		stage(t, dir, name, hostiletest.NewSet(t))
		_ = i
	}
	stage(t, dir, ".staging-mmmm", mine)

	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), mine)
}

func TestHostile_Staging_hostileNamesAreNeverFollowedOrLoggedRaw(t *testing.T) {
	names := []string{
		".staging-..",
		".staging-" + strings.Repeat("a", 200),
		".staging-é\u202e\u200b",
		".staging-\n[ERROR] forged line",
		".staging-\r\x1b[2J\x1b[31m",
		".staging-%s%d%n%!(EXTRA)",
		".staging- ",
		".staging-\x01\x02\x03",
		".staging-\xff\xfe",
		".staging--rf",
	}
	for i, name := range names {
		t.Run("name"+string(rune('A'+i)), func(t *testing.T) {
			if runtime.GOOS == "darwin" && !utf8.ValidString(name) {
				t.Skip("APFS refuses a name that is not valid UTF-8 (EILSEQ), so the entry cannot be created")
			}
			sb := hostiletest.NewSandbox(t)
			mine := hostiletest.NewSet(t)
			dir := privatePlusStaging(t, mine, sb, name)

			r := hostiletest.Open(t, dir, false)

			hostiletest.Loaded(t, r, mine)
			for _, line := range r.Log.Lines {
				if strings.ContainsAny(line, "\x1b\r") || strings.Count(line, "\n") > 0 {
					t.Errorf("a log line carries a raw control character from a file name: %q", line)
				}
			}
			assertNoEscapedEntries(t, sb)
		})
	}
}

// privatePlusStaging builds a partial KeysDir whose only staging directory has
// the given name and holds the full set.
func privatePlusStaging(t *testing.T, s hostiletest.KeySet, sb hostiletest.Sandbox, name string) string {
	t.Helper()
	dir := partialWith(t, sb, s)
	stage(t, dir, name, s)
	return dir
}

// assertNoEscapedEntries checks nothing appeared next to or above KeysDir.
func assertNoEscapedEntries(t *testing.T, sb hostiletest.Sandbox) {
	t.Helper()
	entries, err := os.ReadDir(sb.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // keys and outside
		t.Errorf("the sandbox root gained entries: %v", entries)
	}
	if out, _ := os.ReadDir(sb.Outside); len(out) != 0 {
		t.Errorf("the outside directory gained entries: %v", out)
	}
}

func TestHostile_Staging_lookalikeNamesAreNotStagingDirectories(t *testing.T) {
	for _, name := range []string{".STAGING-x", "staging-x", ".stagin-x", ".staging", " .staging-x", "x.staging-x", ".staging_x"} {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			mine := hostiletest.NewSet(t)
			dir := partialWith(t, sb, mine)
			stage(t, dir, name, mine)

			hostiletest.Refused(t, hostiletest.Open(t, dir, false), mine)
		})
	}
}

func TestHostile_Staging_nonDirectoryStagingEntriesAreIgnored(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	mine := hostiletest.NewSet(t)
	dir := partialWith(t, sb, mine)
	hostiletest.Put(t, filepath.Join(dir, ".staging-file"), mine.PrivPEM, 0o600)
	hostiletest.Mkfifo(t, filepath.Join(dir, ".staging-fifo"))
	hostiletest.Mksocket(t, filepath.Join(dir, ".staging-socket"))
	hostiletest.MustSymlink(t, "/dev/null", filepath.Join(dir, ".staging-null"))

	hostiletest.Refused(t, hostiletest.Open(t, dir, false), mine)
}

func TestHostile_Staging_aStaleStagingNextToAPublishedSetNeverReplacesIt(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		published, stale := hostiletest.NewSet(t), hostiletest.NewSet(t)
		dir := sb.WithSet(t, published)
		stage(t, dir, ".staging-stale", stale)

		r := hostiletest.Open(t, dir, loadOnly)

		hostiletest.Loaded(t, r, published)
		if !r.Log.Has("never published") {
			t.Errorf("the stale staging directory was not reported:\n%s", r.Log.All())
		}
	})
}

func TestHostile_Staging_manyStaleStagingDirectoriesDoNotStallStartup(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	published := hostiletest.NewSet(t)
	dir := sb.WithSet(t, published)
	for i := 0; i < 300; i++ {
		hostiletest.MustMkdir(t, filepath.Join(dir, layout.StagingPrefix+strings.Repeat("0", 5)+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	hostiletest.Loaded(t, hostiletest.Open(t, dir, true), published)
}
