//go:build unix

package hostile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 4: hard links, files replaced during publish, abandoned or foreign
// staging directories and staging directories with hostile names.

func TestHostile_Staging_hardLinksToExternalNonKeyFilesAreRefusedUntouched(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		for _, n := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
			victim := filepath.Join(sb.outside, "victim-"+n)
			put(t, victim, []byte("precious "+n+"\n"), 0o644)
			if err := os.Link(victim, filepath.Join(dir, n)); err != nil {
				t.Skipf("hard links unavailable here: %v", err)
			}
		}
		before := tree(t, sb.outside)

		refused(t, open(t, dir, loadOnly))

		assertSame(t, "outside", before, tree(t, sb.outside))
	})
}

func TestHostile_Staging_hardLinkedExternalCopyOfASetIsReadNeverRewritten(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.keysDir(t)
	s.writeFiles(t, sb.outside)
	for _, n := range layout.KeyFileNames() {
		if err := os.Link(filepath.Join(sb.outside, n), filepath.Join(dir, n)); err != nil {
			t.Skipf("hard links unavailable here: %v", err)
		}
	}
	before := tree(t, sb.outside)

	loaded(t, open(t, dir, true), s)
	loaded(t, open(t, dir, false), s)

	assertSame(t, "outside", before, tree(t, sb.outside))
}

func TestHostile_Staging_regularFilePlantedBetweenCheckAndLinkIsNeverOverwritten(t *testing.T) {
	sb := newSandbox(t)
	dir := sb.keysDir(t)
	planted := []byte("attacker owned, mode 0644\n")
	path := filepath.Join(dir, layout.FilePrivateKey)
	setFault(t, func(point string) error {
		if point == "staged" {
			return os.WriteFile(path, planted, 0o644)
		}
		return nil
	})

	r := open(t, dir, false) // waits out the publish deadline, about five seconds

	refused(t, r)
	if !bytes.Equal(read(t, path), planted) {
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
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			foreign := []byte("not what authcore staged\n")
			path := filepath.Join(dir, c.replaced)
			setFault(t, func(point string) error {
				if point == c.after {
					return os.WriteFile(path, foreign, 0o600)
				}
				return nil
			})

			first := open(t, dir, false)
			refused(t, first)
			if !strings.Contains(first.err.Error(), "two different initialisations") {
				t.Errorf("the refusal does not say what is wrong: %v", first.err)
			}

			setFault(t, func(string) error { return nil })
			// The foreign bytes are not valid key material, so the next start
			// refuses too (as TwoInits while the set is partial, as a parse
			// error once it is complete) and never normalises them.
			refused(t, open(t, dir, false))
			if !bytes.Equal(read(t, path), foreign) {
				t.Error("the foreign file was replaced by recovery")
			}
			if len(stagingDirs(t, dir)) == 0 {
				t.Error("the staging directory, the only copy of the staged keys, was deleted")
			}
		})
	}
}

// abandon leaves a complete, unpublished staging directory by crashing right
// after it was written, and returns its private key file bytes.
func abandon(t *testing.T, dir string) []byte {
	t.Helper()
	crashAt(t, "staged")
	refused(t, open(t, dir, false))
	setFault(t, func(string) error { return nil })
	names := stagingDirs(t, dir)
	if len(names) != 1 {
		t.Fatalf("expected one abandoned staging directory, got %v", names)
	}
	return read(t, filepath.Join(dir, names[0], layout.FilePrivateKey))
}

func TestHostile_Staging_abandonedStagingIsNeverAdoptedByALaterSet(t *testing.T) {
	sb := newSandbox(t)
	dir := sb.keysDir(t)
	stagedPriv := abandon(t, dir)

	r := open(t, dir, false)
	if r.err != nil {
		t.Fatalf("a crash before any link must not block the next start: %v", r.err)
	}
	if bytes.Equal(read(t, filepath.Join(dir, layout.FilePrivateKey)), stagedPriv) {
		t.Fatal("the abandoned staging keys were published without ever being linked")
	}
	if !r.log.has("never published") {
		t.Errorf("the abandoned staging directory was not reported:\n%s", r.log.all())
	}

	// Damage the published set into a partial one: the old staging holds a
	// different private key, so it must not be used to complete it.
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	refused(t, open(t, dir, false))
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s was recreated from a staging directory of another set", n)
		}
	}
}

// partialWith builds a KeysDir holding only the private key of s.
func partialWith(t *testing.T, sb sandbox, s keySet) string {
	t.Helper()
	dir := sb.keysDir(t)
	put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
	return dir
}

// stage writes a staging directory called name holding s.
func stage(t *testing.T, dir, name string, s keySet) string {
	t.Helper()
	st := mustMkdir(t, filepath.Join(dir, name))
	s.writeFiles(t, st)
	return st
}

func TestHostile_Staging_foreignStagingContentIsNotAdopted(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, st string, mine keySet)
	}{
		{"different private", func(t *testing.T, st string, _ keySet) {
			put(t, filepath.Join(st, layout.FilePrivateKey), newSet(t).privPEM, 0o600)
		}},
		{"private is garbage", func(t *testing.T, st string, _ keySet) {
			put(t, filepath.Join(st, layout.FilePrivateKey), []byte("garbage"), 0o600)
		}},
		{"secret file missing", func(t *testing.T, st string, _ keySet) {
			if err := os.Remove(filepath.Join(st, layout.FileRefreshSecret)); err != nil {
				t.Fatal(err)
			}
		}},
		{"public file is a fifo", func(t *testing.T, st string, _ keySet) {
			p := filepath.Join(st, layout.FilePublicKey)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mkfifo(t, p)
		}},
		{"secret file is a directory", func(t *testing.T, st string, _ keySet) {
			p := filepath.Join(st, layout.FileRefreshSecret)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		}},
		{"private is a megabyte", func(t *testing.T, st string, mine keySet) {
			put(t, filepath.Join(st, layout.FilePrivateKey), append(append([]byte{}, mine.privPEM...), bytes.Repeat([]byte("x"), 1<<20)...), 0o600)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sb := newSandbox(t)
			mine := newSet(t)
			dir := partialWith(t, sb, mine)
			st := stage(t, dir, layout.StagingPrefix+"foreign", mine)
			c.build(t, st, mine)

			refused(t, open(t, dir, false), mine)

			for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
				if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
					t.Errorf("%s was linked into KeysDir from the foreign staging directory", n)
				}
			}
		})
	}
}

func TestHostile_Staging_aMatchingStagingAmongForeignOnesIsTheOneAdopted(t *testing.T) {
	sb := newSandbox(t)
	mine := newSet(t)
	dir := partialWith(t, sb, mine)
	for i, name := range []string{".staging-0000", ".staging-zzzz"} {
		stage(t, dir, name, newSet(t))
		_ = i
	}
	stage(t, dir, ".staging-mmmm", mine)

	loaded(t, open(t, dir, false), mine)
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
			sb := newSandbox(t)
			mine := newSet(t)
			dir := mine.privatePlusStaging(t, sb, name)

			r := open(t, dir, false)

			loaded(t, r, mine)
			for _, line := range r.log.lines {
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
func (s keySet) privatePlusStaging(t *testing.T, sb sandbox, name string) string {
	t.Helper()
	dir := partialWith(t, sb, s)
	stage(t, dir, name, s)
	return dir
}

// assertNoEscapedEntries checks nothing appeared next to or above KeysDir.
func assertNoEscapedEntries(t *testing.T, sb sandbox) {
	t.Helper()
	entries, err := os.ReadDir(sb.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // keys and outside
		t.Errorf("the sandbox root gained entries: %v", entries)
	}
	if out, _ := os.ReadDir(sb.outside); len(out) != 0 {
		t.Errorf("the outside directory gained entries: %v", out)
	}
}

func TestHostile_Staging_lookalikeNamesAreNotStagingDirectories(t *testing.T) {
	for _, name := range []string{".STAGING-x", "staging-x", ".stagin-x", ".staging", " .staging-x", "x.staging-x", ".staging_x"} {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			mine := newSet(t)
			dir := partialWith(t, sb, mine)
			stage(t, dir, name, mine)

			refused(t, open(t, dir, false), mine)
		})
	}
}

func TestHostile_Staging_nonDirectoryStagingEntriesAreIgnored(t *testing.T) {
	sb := newSandbox(t)
	mine := newSet(t)
	dir := partialWith(t, sb, mine)
	put(t, filepath.Join(dir, ".staging-file"), mine.privPEM, 0o600)
	mkfifo(t, filepath.Join(dir, ".staging-fifo"))
	mksocket(t, filepath.Join(dir, ".staging-socket"))
	mustSymlink(t, "/dev/null", filepath.Join(dir, ".staging-null"))

	refused(t, open(t, dir, false), mine)
}

func TestHostile_Staging_aStaleStagingNextToAPublishedSetNeverReplacesIt(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		published, stale := newSet(t), newSet(t)
		dir := sb.withSet(t, published)
		stage(t, dir, ".staging-stale", stale)

		r := open(t, dir, loadOnly)

		loaded(t, r, published)
		if !r.log.has("never published") {
			t.Errorf("the stale staging directory was not reported:\n%s", r.log.all())
		}
	})
}

func TestHostile_Staging_manyStaleStagingDirectoriesDoNotStallStartup(t *testing.T) {
	sb := newSandbox(t)
	published := newSet(t)
	dir := sb.withSet(t, published)
	for i := 0; i < 300; i++ {
		mustMkdir(t, filepath.Join(dir, layout.StagingPrefix+strings.Repeat("0", 5)+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	loaded(t, open(t, dir, true), published)
}
